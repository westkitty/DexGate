# DexGate 0.3.0 Build Validation

## Runtime

Generated, compared, merged, and statically checked in a non-macOS Linux runtime, then built and packaged on macOS in `/Users/andrew/DexGate/build_work/DexGate`.

## Validation performed here

| Check | Status | Evidence |
|---|---|---|
| Both input zips unpacked | pass | Previous generated 0.2.0 and uploaded alternate 0.2.0 archives were extracted and compared. |
| Source package created | pass | `Package.swift` exists and names `DexGate`. |
| Swift package manifest parse | pass | `swift package dump-package` completed successfully and output was saved to `qa/package_dump.json`. |
| Core Swift source parse | pass | `swiftc -parse` passed for `Models.swift`, `ScannerRules.swift`, `Analyzer.swift`, `LocalCommandRunner.swift`, and `RunnerProfileFactory.swift`. |
| Static project preflight | pass | `bash scripts/preflight_static.sh` completed with exit code 0; output saved to `qa/preflight_static.log`. |
| Stale previous-name check | pass | Preflight found no stale predecessor app name strings outside the preflight check itself. |
| Zip integrity | pass | Final source zip was tested with `unzip -t`. |
| Native macOS build | pass | `swift build -c release` completed successfully on macOS after small source compatibility fixes. |
| Linux `swift build` | expected fail | Fails at `import AppKit`, which is expected outside macOS. See `qa/linux_swift_build_attempt.log`. |
| Package bundle build | pass | `bash scripts/build_app.sh` produced `dist/DexGate.app`, `dist/DexGate-macOS-unsigned.zip`, and `dist/CHECKSUMS.sha256`. |
| GUI launch | partial | `open dist/DexGate.app` launched the app process, but no interactive window-level smoke test was performed here. |
| Signing/notarization | not performed | Build script only performs ad-hoc signing when available; no Developer ID signing or notarization was done. |

## Commands run here

```bash
unzip -q DexGate-0.2.0-source.zip
unzip -q DexGate-0.2.0-source(2).zip
bash scripts/preflight_static.sh
swift package dump-package
swiftc -parse Sources/DexGate/Models.swift Sources/DexGate/ScannerRules.swift Sources/DexGate/Analyzer.swift Sources/DexGate/LocalCommandRunner.swift Sources/DexGate/RunnerProfileFactory.swift
swift build -c release
zip -r DexGate-0.3.0-optimal-source.zip DexGate
unzip -t DexGate-0.3.0-optimal-source.zip
swift build -c release
bash scripts/build_app.sh
test -d dist/DexGate.app
test -x dist/DexGate.app/Contents/MacOS/DexGate
plutil -lint dist/DexGate.app/Contents/Info.plist
codesign --verify --deep --strict --verbose=2 dist/DexGate.app || true
shasum -a 256 dist/DexGate-macOS-unsigned.zip
unzip -t dist/DexGate-macOS-unsigned.zip
grep -RInE 'URLSession|NSURLConnection|fetch\\(|curl|wget|VirusTotal|telemetry|analytics|openai|anthropic|apiKey|api_key|http://|https://' Sources scripts Package.swift README.md || true
open dist/DexGate.app
```

## Expected macOS validation path

Run from the project root on macOS:

```bash
bash scripts/preflight_static.sh
swift build -c release
bash scripts/build_app.sh
open dist/DexGate.app
```

Then manually test drag/drop, Choose Script, risk score, danger map, rewrites, dependency tab, all six runner profiles, Markdown export, and private audit bundle export.
