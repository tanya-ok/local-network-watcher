#!/bin/zsh
set -eu

SCRIPT_DIR="$(cd "$(/usr/bin/dirname "$0")" && /bin/pwd)"
PROJECT="$(cd "$SCRIPT_DIR/../.." && /bin/pwd)"
export PATH="/opt/homebrew/bin:/usr/local/bin:$HOME/.cargo/bin:/usr/bin:/bin:/usr/sbin:/sbin"
NODE="$(command -v node)"
CARGO="$(command -v cargo)"
URL="http://127.0.0.1:4317/"
LOG_DIR="$HOME/Library/Logs"
LOG_FILE="$LOG_DIR/LocalNetworkWatcher.log"

if /usr/bin/curl --silent --fail --max-time 1 "$URL" >/dev/null 2>&1; then
  exit 0
fi

if [[ ! -x "$PROJECT/target/debug/netwatch-core" ]]; then
  "$CARGO" build --manifest-path "$PROJECT/Cargo.toml"
fi

/bin/mkdir -p "$LOG_DIR"
/usr/bin/nohup "$NODE" "$PROJECT/server.js" >>"$LOG_FILE" 2>&1 </dev/null &

for attempt in {1..30}; do
  if /usr/bin/curl --silent --fail --max-time 1 "$URL" >/dev/null 2>&1; then
    exit 0
  fi
  /bin/sleep 1
done

echo "Local Network Watcher did not start. See $LOG_FILE" >&2
exit 1
