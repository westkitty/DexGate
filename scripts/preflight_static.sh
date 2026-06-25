#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

echo "== Files =="
find . -path './.build' -prune -o -maxdepth 4 -type f -print | sort

echo "== Swift package description =="
sed -n '1,200p' Package.swift

echo "== Package parse =="
if command -v swift >/dev/null 2>&1; then
  swift package dump-package >/tmp/dexgate-package.json
  echo "PASS: swift package dump-package"
else
  echo "WARN: swift not installed"
fi

echo "== Risky build-script operations =="
grep -RInE 'curl|wget|sudo|rm -rf|codesign|notarytool|spctl|launchctl|osascript|security ' scripts Sources --exclude-dir=.build || true

echo "== Privacy check: network-like strings =="
grep -RInE 'http://|https://|URLSession|NSURLConnection|curl|wget' Sources scripts README.md --exclude-dir=.build || true

echo "== Name check =="
OLD_NAME="Script""Sentry"
if grep -RIn "$OLD_NAME" . --exclude-dir=.build --exclude='preflight_static.sh' --exclude='preflight_static.log' --exclude='linux_swift_build_attempt.log'; then
  echo "FAIL: stale previous app name found" >&2
  exit 1
else
  echo "PASS: no stale previous app name strings"
fi

echo "== Done =="
