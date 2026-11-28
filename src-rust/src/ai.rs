//! Explanations from a model on this Mac only: Ollama on loopback.

use serde_json::{Value, json};
use std::time::Duration;

const OLLAMA: &str = "http://127.0.0.1:11434";

pub fn model() -> String {
    std::env::var("EXPLAIN_MODEL").unwrap_or_else(|_| "gemma4:26b".into())
}

fn agent(timeout: Duration) -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout(timeout)
        .redirects(0)
        .build()
}

/// Blocking call; run it on a blocking thread.
pub fn chat(system: &str, user: &str, max_tokens: u32) -> Result<String, String> {
    let body = json!({
        "model": model(),
        "stream": false,
        "think": false,
        "options": { "temperature": 0.2, "num_predict": max_tokens },
        "messages": [
            { "role": "system", "content": system },
            { "role": "user", "content": user },
        ],
    });
    let response = agent(Duration::from_secs(120))
        .post(&format!("{OLLAMA}/api/chat"))
        .send_json(body)
        .map_err(|e| match e {
            ureq::Error::Status(code, _) => format!("Local model returned {code}"),
            _ => "The local model did not answer".to_string(),
        })?;
    let data: Value = response
        .into_json()
        .map_err(|_| "The local model sent an unreadable answer".to_string())?;
    let text = data["message"]["content"]
        .as_str()
        .unwrap_or("")
        .trim()
        .to_string();
    Ok(if text.is_empty() {
        "No answer.".into()
    } else {
        text
    })
}

pub fn models() -> Result<Vec<String>, String> {
    let response = agent(Duration::from_millis(2500))
        .get(&format!("{OLLAMA}/api/tags"))
        .call()
        .map_err(|_| "Ollama is not reachable on this Mac.".to_string())?;
    let data: Value = response
        .into_json()
        .map_err(|_| "Ollama sent an unreadable answer".to_string())?;
    Ok(data["models"]
        .as_array()
        .map(|list| {
            list.iter()
                .filter_map(|m| m["name"].as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default())
}

pub const EXPLAIN_SYSTEM: &str = "You explain network activity on a personal Mac to its owner, calmly and plainly, in English, without long dashes. Use only the facts given. If you do not know who owns an address, say so. Never claim something is malicious without evidence. Answer in at most four short sentences: what this probably is, whether it looks normal, and one thing to check if unsure.";

pub const ASK_SYSTEM: &str = "You are a cautious network investigation helper for a Mac user. Explain concepts in plain English. Do not claim maliciousness without evidence, and do not suggest executing shell commands. State uncertainty.";

/// `key: value` lines from a JSON object, each value cut to 200 characters.
pub fn facts_from(object: &serde_json::Map<String, Value>, allowed: Option<&[&str]>) -> String {
    object
        .iter()
        .filter(|(k, _)| allowed.is_none_or(|list| list.contains(&k.as_str())))
        .filter_map(|(k, v)| {
            let text = match v {
                Value::Null => return None,
                Value::String(s) if s.is_empty() => return None,
                Value::String(s) => s.clone(),
                other => other.to_string(),
            };
            Some(format!(
                "{k}: {}",
                text.chars().take(200).collect::<String>()
            ))
        })
        .collect::<Vec<_>>()
        .join("\n")
}

const REVIEW_SYSTEM: &str = r#"You review network attention markers from a personal Mac for its owner.
Each marker has an id, the app, its trust tier (from code signature and folder), the kind of event, the destination and a reason.
For each marker decide:
- "normal": a well-known, expected pattern for this app and destination (for example a browser or system service reaching its vendor or a CDN).
- "suspicious": anything you cannot explain from the facts, unusual ports for the app, unknown destinations for a background tool, large uploads, or weak trust.
When unsure, answer "suspicious". Never invent facts.
Reply with JSON only: {"reviews":[{"id":"...","verdict":"normal"|"suspicious","reason":"one short plain English sentence, no long dashes"}]}"#;

/// Trust tiers whose markers the model may clear. Unsigned, ad hoc and temp-folder apps always stay for a person.
pub fn clearable(tier: &str) -> bool {
    matches!(tier, "apple-system" | "signed" | "unknown" | "")
}

/// Sorts up to 20 markers into normal and suspicious. Returns (id, verdict, reason). Blocking.
pub fn review_markers(items: Vec<Value>) -> Result<Vec<(String, String, String)>, String> {
    if items.is_empty() {
        return Ok(Vec::new());
    }
    let ids: Vec<String> = items
        .iter()
        .filter_map(|i| i["id"].as_str().map(str::to_string))
        .collect();
    let body = json!({
        "model": model(), "stream": false, "think": false, "format": "json",
        "options": { "temperature": 0.1, "num_predict": 120 * items.len() + 200 },
        "messages": [
            { "role": "system", "content": REVIEW_SYSTEM },
            { "role": "user", "content": json!({ "markers": items }).to_string() },
        ],
    });
    let response = agent(Duration::from_secs(240))
        .post(&format!("{OLLAMA}/api/chat"))
        .send_json(body)
        .map_err(|e| match e {
            ureq::Error::Status(code, _) => format!("Local model returned {code}"),
            _ => "The local model did not answer".to_string(),
        })?;
    let data: Value = response
        .into_json()
        .map_err(|_| "The local model sent an unreadable answer".to_string())?;
    let parsed: Value = serde_json::from_str(data["message"]["content"].as_str().unwrap_or("{}"))
        .map_err(|_| "The local model did not return valid JSON".to_string())?;
    Ok(parsed["reviews"]
        .as_array()
        .map(|list| {
            list.iter()
                .filter_map(|r| {
                    let id = r["id"].as_str()?;
                    let verdict = r["verdict"].as_str()?;
                    if !ids.iter().any(|i| i == id) || !matches!(verdict, "normal" | "suspicious") {
                        return None;
                    }
                    let reason: String = r["reason"]
                        .as_str()
                        .unwrap_or("")
                        .replace(['\u{2013}', '\u{2014}'], "-")
                        .chars()
                        .take(300)
                        .collect();
                    Some((id.to_string(), verdict.to_string(), reason))
                })
                .collect()
        })
        .unwrap_or_default())
}
