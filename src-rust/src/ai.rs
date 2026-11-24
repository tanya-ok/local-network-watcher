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
