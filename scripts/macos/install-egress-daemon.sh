#!/bin/bash
# Installs the egress proxy as a system LaunchDaemon under a hidden service account.
# Run as the owner: sudo scripts/macos/install-egress-daemon.sh [--binary PATH] [--dns]
# --dns also installs a root LaunchDaemon that logs DNS queries from pflog0 for the journal.
# Idempotent: running it again updates the binary and the plists and restarts the jobs.
set -euo pipefail

ACCOUNT=_localwatch
LABEL=com.localwatch.egress
RUNDIR_LABEL=com.localwatch.egress-rundir
DNS_LABEL=com.localwatch.egress-dns
PREFIX=/usr/local/libexec/local-watch-egress
BIN="$PREFIX/local-network-watcher"
DATA="/Library/Application Support/LocalWatchEgress"
RUN=/var/run/local-watch-egress
LOGDIR=/var/log/local-watch-egress
DNSLOG="$LOGDIR/dns.log"
DAEMONS=/Library/LaunchDaemons

HERE="$(cd "$(/usr/bin/dirname "$0")" && /bin/pwd)"
ROOT="$(cd "$HERE/../.." && /bin/pwd)"
SOURCE="$ROOT/target/release/local-network-watcher"
WITH_DNS=0

while [ $# -gt 0 ]; do
  case "$1" in
    --binary) SOURCE="$2"; shift 2 ;;
    --dns) WITH_DNS=1; shift ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
done

if [ "$(/usr/bin/id -u)" -ne 0 ]; then
  echo "Run with sudo." >&2
  exit 1
fi
if [ ! -x "$SOURCE" ]; then
  echo "No binary at $SOURCE. Build it first as yourself: cargo build --release --locked" >&2
  exit 1
fi

used_ids() {
  /usr/bin/dscl . -list /Users UniqueID | /usr/bin/awk '{print $2}'
  /usr/bin/dscl . -list /Groups PrimaryGroupID | /usr/bin/awk '{print $2}'
}

if /usr/bin/dscl . -read "/Users/$ACCOUNT" UniqueID >/dev/null 2>&1; then
  ID="$(/usr/bin/dscl . -read "/Users/$ACCOUNT" UniqueID | /usr/bin/awk '{print $2}')"
  echo "Service account $ACCOUNT exists (uid $ID)."
else
  ID=""
  USED="$(used_ids | /usr/bin/sort -n | /usr/bin/uniq)"
  for candidate in $(/usr/bin/seq 480 -1 300); do
    if ! printf '%s\n' "$USED" | /usr/bin/grep -qx "$candidate"; then
      ID="$candidate"
      break
    fi
  done
  if [ -z "$ID" ]; then
    echo "No free id between 300 and 480." >&2
    exit 1
  fi
  echo "Creating service account $ACCOUNT with uid and gid $ID."
  if ! /usr/bin/dscl . -read "/Groups/$ACCOUNT" >/dev/null 2>&1; then
    /usr/bin/dscl . -create "/Groups/$ACCOUNT"
    /usr/bin/dscl . -create "/Groups/$ACCOUNT" PrimaryGroupID "$ID"
    /usr/bin/dscl . -create "/Groups/$ACCOUNT" RealName "Local Network Watcher egress"
    /usr/bin/dscl . -create "/Groups/$ACCOUNT" Password '*'
  fi
  /usr/bin/dscl . -create "/Users/$ACCOUNT"
  /usr/bin/dscl . -create "/Users/$ACCOUNT" UniqueID "$ID"
  /usr/bin/dscl . -create "/Users/$ACCOUNT" PrimaryGroupID "$(/usr/bin/dscl . -read "/Groups/$ACCOUNT" PrimaryGroupID | /usr/bin/awk '{print $2}')"
  /usr/bin/dscl . -create "/Users/$ACCOUNT" UserShell /usr/bin/false
  /usr/bin/dscl . -create "/Users/$ACCOUNT" NFSHomeDirectory /var/empty
  /usr/bin/dscl . -create "/Users/$ACCOUNT" RealName "Local Network Watcher egress"
  /usr/bin/dscl . -create "/Users/$ACCOUNT" Password '*'
  /usr/bin/dscl . -create "/Users/$ACCOUNT" IsHidden 1
fi

# Root-owned binary: the service account cannot replace its own code.
/usr/bin/install -d -o root -g wheel -m 0755 "$PREFIX"
/usr/bin/install -o root -g wheel -m 0755 "$SOURCE" "$BIN.new"
/bin/mv -f "$BIN.new" "$BIN"

/usr/bin/install -d -o "$ACCOUNT" -g "$ACCOUNT" -m 0700 "$DATA"
/usr/sbin/chown -R "$ACCOUNT:$ACCOUNT" "$DATA"
/bin/chmod 0700 "$DATA"
/usr/bin/find "$DATA" -type f -exec /bin/chmod 0600 {} +
/usr/bin/install -d -o "$ACCOUNT" -g "$ACCOUNT" -m 0755 "$RUN"

write_plist() {
  /usr/bin/install -o root -g wheel -m 0644 /dev/null "$1"
  /bin/cat > "$1"
  /usr/bin/plutil -lint "$1" >/dev/null
}

# /var/run is emptied at boot; this one-shot root job recreates the socket directory.
write_plist "$DAEMONS/$RUNDIR_LABEL.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>$RUNDIR_LABEL</string>
  <key>ProgramArguments</key>
  <array>
    <string>/usr/bin/install</string><string>-d</string>
    <string>-o</string><string>$ACCOUNT</string><string>-g</string><string>$ACCOUNT</string>
    <string>-m</string><string>0755</string><string>$RUN</string>
  </array>
  <key>RunAtLoad</key><true/>
</dict>
</plist>
EOF

write_plist "$DAEMONS/$LABEL.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>$LABEL</string>
  <key>ProgramArguments</key>
  <array><string>$BIN</string><string>egress-daemon</string></array>
  <key>UserName</key><string>$ACCOUNT</string>
  <key>GroupName</key><string>$ACCOUNT</string>
  <key>EnvironmentVariables</key>
  <dict>
    <key>LOCAL_WATCH_EGRESS_DATA</key><string>$DATA</string>
    <key>LOCAL_WATCH_EGRESS_SOCKET</key><string>$RUN/control.sock</string>
    <key>LOCAL_WATCH_EGRESS_DNS_LOG</key><string>$DNSLOG</string>
    <key>HOME</key><string>/var/empty</string>
  </dict>
  <key>Umask</key><integer>63</integer>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ThrottleInterval</key><integer>10</integer>
  <key>StandardErrorPath</key><string>$DATA/daemon.err</string>
</dict>
</plist>
EOF

reload() {
  /bin/launchctl bootout "system/$1" 2>/dev/null || true
  /bin/launchctl bootstrap system "$DAEMONS/$1.plist"
}

if [ "$WITH_DNS" -eq 1 ]; then
  /usr/bin/install -d -o root -g "$ACCOUNT" -m 0750 "$LOGDIR"
  /usr/bin/install -o root -g wheel -m 0755 /dev/null "$PREFIX/dns-log.sh"
  /bin/cat > "$PREFIX/dns-log.sh" <<EOF
#!/bin/sh
# Root job: DNS query lines seen on pflog0, readable by $ACCOUNT only. Rotation by newsyslog.
umask 027
/sbin/ifconfig pflog0 create 2>/dev/null || true
/usr/bin/touch "$DNSLOG"
/usr/sbin/chown root:$ACCOUNT "$DNSLOG"
/bin/chmod 0640 "$DNSLOG"
# Appending per line keeps writing to the current file after newsyslog rotates it.
/usr/sbin/tcpdump -l -n -i pflog0 udp port 53 2>/dev/null | while IFS= read -r line; do
  printf '%s\\n' "\$line" >> "$DNSLOG"
done
EOF
  /bin/chmod 0755 "$PREFIX/dns-log.sh"
  /usr/bin/install -o root -g wheel -m 0644 /dev/null /etc/newsyslog.d/local-watch-egress.conf
  printf '%s\troot:%s\t640\t3\t5120\t*\tN\n' "$DNSLOG" "$ACCOUNT" > /etc/newsyslog.d/local-watch-egress.conf
  write_plist "$DAEMONS/$DNS_LABEL.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>$DNS_LABEL</string>
  <key>ProgramArguments</key><array><string>$PREFIX/dns-log.sh</string></array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ThrottleInterval</key><integer>10</integer>
</dict>
</plist>
EOF
fi

reload "$RUNDIR_LABEL"
reload "$LABEL"
if [ "$WITH_DNS" -eq 1 ]; then
  reload "$DNS_LABEL"
fi

echo "Installed. Control socket: $RUN/control.sock. Data: $DATA (owner $ACCOUNT, 0700)."
echo "Check: $BIN egress status"
echo "Restart the Local Network Watcher app so it finds the daemon and leaves the proxy ports to it."
