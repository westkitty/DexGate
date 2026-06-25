#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APP_NAME="DexGate"
BUNDLE_ID="com.stinkyweasel.dexgate"
VERSION="0.3.0"
BUILD="1"
DIST="$ROOT/dist"
APP="$DIST/$APP_NAME.app"
EXEC="$APP/Contents/MacOS/$APP_NAME"

cd "$ROOT"

if ! command -v swift >/dev/null 2>&1; then
  echo "FAIL: swift was not found. Install Xcode command line tools or full Xcode." >&2
  exit 1
fi

rm -rf "$DIST"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"

swift build -c release
cp "$ROOT/.build/release/$APP_NAME" "$EXEC"
chmod 755 "$EXEC"

cat > "$APP/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleDevelopmentRegion</key>
  <string>en</string>
  <key>CFBundleExecutable</key>
  <string>$APP_NAME</string>
  <key>CFBundleIdentifier</key>
  <string>$BUNDLE_ID</string>
  <key>CFBundleInfoDictionaryVersion</key>
  <string>6.0</string>
  <key>CFBundleName</key>
  <string>$APP_NAME</string>
  <key>CFBundleDisplayName</key>
  <string>$APP_NAME</string>
  <key>CFBundlePackageType</key>
  <string>APPL</string>
  <key>CFBundleShortVersionString</key>
  <string>$VERSION</string>
  <key>CFBundleVersion</key>
  <string>$BUILD</string>
  <key>LSMinimumSystemVersion</key>
  <string>13.0</string>
  <key>NSHighResolutionCapable</key>
  <true/>
  <key>NSSupportsAutomaticGraphicsSwitching</key>
  <true/>
</dict>
</plist>
PLIST

# Ad-hoc sign for local launch convenience. This is not Developer ID signing and not notarization.
if command -v codesign >/dev/null 2>&1; then
  codesign --force --deep --sign - "$APP" || true
fi

if command -v plutil >/dev/null 2>&1; then
  plutil -lint "$APP/Contents/Info.plist"
fi

if command -v codesign >/dev/null 2>&1; then
  codesign --verify --deep --strict --verbose=2 "$APP" || true
fi

cd "$DIST"
/usr/bin/ditto -c -k --keepParent "$APP_NAME.app" "$APP_NAME-macOS-unsigned.zip"
shasum -a 256 "$APP_NAME-macOS-unsigned.zip" > CHECKSUMS.sha256

echo "Built: $APP"
echo "Zip: $DIST/$APP_NAME-macOS-unsigned.zip"
echo "Checksums: $DIST/CHECKSUMS.sha256"
