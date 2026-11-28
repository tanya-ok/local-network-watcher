#!/bin/zsh
# Builds the release binary and installs "Local Network Watcher.app" into ~/Applications.
# Optional: --dock adds the app to the Dock once.
set -eu

HERE="$(cd "$(/usr/bin/dirname "$0")" && /bin/pwd)"
ROOT="$(cd "$HERE/../.." && /bin/pwd)"
APP="$HOME/Applications/Local Network Watcher.app"
export PATH="$HOME/.cargo/bin:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"

cargo build --release --locked --manifest-path "$ROOT/Cargo.toml"

# A running copy keeps the old binary; stop it so the new one starts on next launch.
/usr/bin/pkill -f "Local Network Watcher.app/Contents/Resources/local-network-watcher" || true

/bin/mkdir -p "$HOME/Applications"
/bin/rm -rf "$APP"
/usr/bin/osacompile -o "$APP" "$HERE/launcher.applescript"
/bin/cp "$ROOT/target/release/local-network-watcher" "$APP/Contents/Resources/local-network-watcher"

if command -v rsvg-convert >/dev/null; then
  ICONSET="$(/usr/bin/mktemp -d)/app.iconset"
  /bin/mkdir -p "$ICONSET"
  for size in 16 32 128 256 512; do
    rsvg-convert -w $size -h $size "$HERE/icon.svg" -o "$ICONSET/icon_${size}x${size}.png"
    rsvg-convert -w $((size * 2)) -h $((size * 2)) "$HERE/icon.svg" -o "$ICONSET/icon_${size}x${size}@2x.png"
  done
  /usr/bin/iconutil -c icns "$ICONSET" -o "$APP/Contents/Resources/applet.icns"
fi

/usr/libexec/PlistBuddy -c "Set :CFBundleName Local Network Watcher" "$APP/Contents/Info.plist"
/usr/libexec/PlistBuddy -c "Add :CFBundleIdentifier string io.github.tanya-ok.local-network-watcher" "$APP/Contents/Info.plist" 2>/dev/null \
  || /usr/libexec/PlistBuddy -c "Set :CFBundleIdentifier io.github.tanya-ok.local-network-watcher" "$APP/Contents/Info.plist"
# osacompile ships Assets.car with the default script icon, which wins over applet.icns.
/bin/rm -f "$APP/Contents/Resources/Assets.car"
/usr/libexec/PlistBuddy -c "Delete :CFBundleIconName" "$APP/Contents/Info.plist" 2>/dev/null || true
/usr/bin/codesign --force --deep --sign - "$APP"
/usr/bin/touch "$APP"

if [[ "${1:-}" == "--dock" ]]; then
  if ! /usr/bin/defaults read com.apple.dock persistent-apps | /usr/bin/grep -q "Local%20Network%20Watcher.app"; then
    /usr/bin/defaults write com.apple.dock persistent-apps -array-add \
      "<dict><key>tile-data</key><dict><key>file-data</key><dict><key>_CFURLString</key><string>$APP</string><key>_CFURLStringType</key><integer>0</integer></dict></dict></dict>"
    /usr/bin/killall Dock
  fi
fi

echo "Installed $APP"
