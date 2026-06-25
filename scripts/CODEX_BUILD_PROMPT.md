# Codex Build Prompt: DexGate 0.3.0 Optimal

```text
You are working on DexGate, a private local-first macOS SwiftUI app for script safety inspection.

Objective:
Compile, fix if needed, test, and package DexGate as a local unsigned macOS app bundle and zip.

Repository / folder:
Use the folder containing this prompt as the project root. Do not rename the app. The app name is DexGate.

Context:
DexGate is a Swift Package Manager macOS GUI app. It lets the user drag/drop or choose a script, then performs local-only static inspection. It must not upload scripts, call online scanners, call AI services, or run the selected script on the host. It may run syntax-only tools like bash -n, zsh -n, python3 -m py_compile, node --check, and shellcheck if installed. It generates disposable runner commands for manual review.

Features expected in this version:
1. Explainable 0-100 risk score with category breakdown.
2. Danger map that highlights risky script lines.
3. Safer rewrite suggestions with copy-to-clipboard.
4. Dependency manifest auditing for package.json, lockfiles, .npmrc, requirements.txt, pyproject.toml, setup.py, Cargo.toml, go.mod, Gemfile, Makefile, Docker/compose/task files.
5. Visible offline lock. No network client code.
6. Disposable runner profile system with Syntax Only, Docker Inspect, Temp Folder Review, Docker Dry Run, Docker Trace, and Audit Bundle guidance.
8. Private audit bundle export with original script copy, Markdown report, JSON findings, runner commands, and checksums.

Required workflow:
1. Inspect Package.swift, Sources/DexGate/*.swift, scripts/build_app.sh, scripts/preflight_static.sh, README.md, and qa/BUILD_VALIDATION.md before editing.
2. Run: bash scripts/preflight_static.sh
3. Build from source: swift build -c release
4. If compilation fails, fix the smallest necessary source issues. Preserve the privacy model and no-host-execution model.
5. Run: bash scripts/build_app.sh
6. Confirm these exist:
   - dist/DexGate.app
   - dist/DexGate-macOS-unsigned.zip
   - dist/CHECKSUMS.sha256
7. Launch-test the app from the built app bundle if the environment supports GUI launch.
8. Test with examples/suspicious-demo.sh and examples/boring-demo.sh.
9. Verify the app does not contain stale predecessor names.
10. Verify there is no URLSession or NSURLConnection client code.

Hard constraints:
- Do not add cloud scanning.
- Do not add VirusTotal integration.
- Do not add AI/API upload behavior.
- Do not auto-run the selected script on the host.
- Do not request sudo/admin privileges.
- Do not create LaunchAgents, Login Items, shell profile edits, or persistence.
- Do not sign with Developer ID unless the user explicitly provides signing identity and asks for it.
- Do not claim notarization unless notarization was actually performed and validated.

Acceptance criteria:
- `swift build -c release` passes on macOS.
- `bash scripts/build_app.sh` produces `dist/DexGate.app` and `dist/DexGate-macOS-unsigned.zip`.
- Drag/drop and Choose Script both trigger analysis.
- Risk Score tab shows score and category breakdown.
- Danger Map tab highlights matched lines.
- Rewrites tab shows suggestions for detected high-risk patterns.
- Dependencies tab reports adjacent manifest findings.
- Offline lock is visible and disabled/enforced.
- Runner Profiles tab displays all six profiles with copyable commands.
- Export Markdown Report works.
- Export Private Audit Bundle writes a local folder with README, copied original, JSON reports, commands, and checksums.
- No stale predecessor names remain in user-facing app/source/docs except intentional historical notes.

Report back with:
- commands run
- files changed
- build result
- app zip path
- test result for suspicious-demo.sh and boring-demo.sh
- any remaining warnings or not-tested items
```
