# DexGate 0.3.0 Manifest

| Path | Role | Status | Purpose |
|---|---|---|---|
| `Package.swift` | source | included | Swift Package Manager manifest for DexGate. |
| `Sources/DexGate/DexGateApp.swift` | source | included | App entry point. |
| `Sources/DexGate/ContentView.swift` | source | included | Main SwiftUI GUI, tabs, drag/drop, exports. |
| `Sources/DexGate/Models.swift` | source | included | Data models, risk score, risk weighting, report structures. |
| `Sources/DexGate/Analyzer.swift` | source | included | Local static scanner, dependency manifest auditing, rewrite suggestion generator. |
| `Sources/DexGate/ScannerRules.swift` | source | included | Static risk rules. |
| `Sources/DexGate/LocalCommandRunner.swift` | source | included | Optional syntax-only local tool runner. |
| `Sources/DexGate/RunnerProfileFactory.swift` | source | included | Centralized disposable runner profile generator. |
| `scripts/build_app.sh` | build | included | macOS app bundle and unsigned zip builder. |
| `scripts/preflight_static.sh` | qa | included | Static project inspection script. |
| `scripts/CODEX_BUILD_PROMPT.md` | handoff | included | Codex build/fix/package prompt. |
| `examples/suspicious-demo.sh` | test input | included | Demo script expected to produce critical/high findings. |
| `examples/boring-demo.sh` | test input | included | Demo script expected to be mostly quiet. |
| `examples/package.json` | test input | included | Dependency-audit fixture for npm lifecycle/version checks. |
| `examples/requirements.txt` | test input | included | Dependency-audit fixture for Python version checks. |
| `README.md` | docs | included | Build, usage, privacy, safety, and limitations. |
| `RELEASE_NOTES.md` | docs | included | Version changes. |
| `COMPARE_AND_MERGE_NOTES.md` | docs | included | Compare/contrast result and merge rationale. |
| `qa/BUILD_VALIDATION.md` | qa | included | Validation status from this runtime. |
| `qa/preflight_static.log` | qa | included | Static preflight output. |
| `qa/core_swift_parse.log` | qa | included | Core Swift parse output. |
| `qa/linux_swift_build_attempt.log` | qa | included | Expected Linux build failure showing missing AppKit. |
| `qa/package_dump.json` | qa | included | Swift package dump output. |
| `CHECKSUMS.sha256` | qa | generated | SHA-256 checksums for source bundle contents. |
