#!/bin/bash
# Removes the egress LaunchDaemons and the installed binary.
# Run as the owner: sudo scripts/macos/uninstall-egress-daemon.sh [--purge]
# --purge also deletes the journal, the policy, the DNS log and the _localwatch account.
set -euo pipefail

ACCOUNT=_localwatch
PREFIX=/usr/local/libexec/local-watch-egress
DATA="/Library/Application Support/LocalWatchEgress"
RUN=/var/run/local-watch-egress
LOGDIR=/var/log/local-watch-egress
DAEMONS=/Library/LaunchDaemons
PURGE=0

if [ "${1:-}" = "--purge" ]; then
  PURGE=1
elif [ $# -gt 0 ]; then
  echo "Unknown option: $1" >&2
  exit 2
fi
if [ "$(/usr/bin/id -u)" -ne 0 ]; then
  echo "Run with sudo." >&2
  exit 1
fi

for label in com.localwatch.egress-dns com.localwatch.egress com.localwatch.egress-rundir; do
  /bin/launchctl bootout "system/$label" 2>/dev/null || true
  /bin/rm -f "$DAEMONS/$label.plist"
done
/bin/rm -rf "$PREFIX" "$RUN"
/bin/rm -f /etc/newsyslog.d/local-watch-egress.conf

if [ "$PURGE" -eq 1 ]; then
  /bin/rm -rf "$DATA" "$LOGDIR"
  if /usr/bin/dscl . -read "/Users/$ACCOUNT" >/dev/null 2>&1; then
    /usr/bin/dscl . -delete "/Users/$ACCOUNT"
  fi
  if /usr/bin/dscl . -read "/Groups/$ACCOUNT" >/dev/null 2>&1; then
    /usr/bin/dscl . -delete "/Groups/$ACCOUNT"
  fi
  echo "Removed the daemons, the data, the DNS log and the $ACCOUNT account."
else
  echo "Removed the daemons. Kept $DATA, $LOGDIR and the $ACCOUNT account; use --purge to delete them."
fi
echo "Restart the Local Network Watcher app so it runs the proxy in-process again, if enabled."
