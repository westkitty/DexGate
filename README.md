# DexGate

DexGate is a private macOS GUI app for local-first script safety inspection.

It does not certify scripts as safe. It gives you a hard gate before a script touches your real account, files, credentials, network, or system settings. Subtle difference. Life-saving difference.

## Optimal 0.3.0 merge

This version merges the better pieces from both 0.2.0 variants:

- keeps the uploaded version's stronger risk scoring model, category breakdowns, richer dependency auditing, private audit bundle export, and compile-friendly conditional CryptoKit fallback
- keeps the previous generated version's broader containment profile intent, fuller test fixture set, and more explicit release documentation
- removes duplicate runner profile generation by centralizing profiles in `RunnerProfileFactory.swift`
- expands runner profiles to cover syntax-only, no-network Docker inspection, temp-folder host review, no-network contained dry run, Docker trace execution, and audit bundle guidance

## Implemented features

1. **Explainable risk score**
   - 0-100 visible score
   - raw point total
   - severity/category weighting
   - category breakdown for network, credentials, persistence, destructive operations, shell execution, dependencies, and more

2. **Danger map**
   - read-only line-by-line script view
   - risky lines highlighted
   - matched rule IDs shown inline

3. **Safer rewrite suggestions**
   - safer patterns for pipe-to-shell, remote downloads, `sudo`, destructive deletion, persistence, credential access, obfuscation, and dependency hazards
   - copy-to-clipboard support for safer patterns

4. **Dependency manifest auditing**
   - checks adjacent files such as `package.json`, lockfiles, `.npmrc`, `requirements.txt`, `pyproject.toml`, `setup.py`, `Cargo.toml`, `go.mod`, `Gemfile`, `Makefile`, Docker/compose files, and task files
   - flags lifecycle scripts, remote dependencies, loose versions, custom package indexes, editable installs, and risky Makefile/package scripts

5. **Offline mode enforcement**
   - visible offline lock in the UI
   - no cloud upload or online scanner behavior
   - no URLSession/NSURLConnection client code
   - generated Docker execution profiles use `--network none`

6. **DMG container inspection**
   - accepts `.dmg` files for local inspection
   - mounts disk images read-only for text and manifest analysis
   - prefixes findings with the inner path so container contents stay readable
   - includes a clear-selection action so you can empty the current item and start over

7. **Disposable runner profile system**
   - Syntax Only
   - Docker Inspect
   - Temp Folder Review
   - Docker Dry Run
   - Docker Trace
   - Audit Bundle guidance
   - copy command button
   - commands are generated for manual review; DexGate does not run selected scripts on the host

8. **Private audit bundle export**
   - exports a local folder containing:
     - copied original script
     - Markdown report
     - static findings JSON
     - dependency findings JSON
     - risk score JSON
     - rewrite suggestions JSON
     - local tool output JSON
     - runner profile commands
     - SHA-256 checksums

## What DexGate does not do

DexGate does **not** prove a script is safe.

It does not:

- upload scripts to VirusTotal or cloud scanners
- call AI services
- execute the selected script normally on the host
- request admin privileges
- install dependencies
- modify shell profile files
- create persistence
- sign or notarize itself

## Build requirements

- macOS 13 or newer
- Xcode command line tools or full Xcode
- Swift 5.9 or newer recommended
- Optional: Docker, ShellCheck, Node, Python 3

## Build the app bundle

From this folder on macOS:

```bash
bash scripts/build_app.sh
```

The script creates:

```text
dist/DexGate.app
dist/DexGate-macOS-unsigned.zip
dist/CHECKSUMS.sha256
```

The app is unsigned/ad-hoc signed unless you edit the build script to use a Developer ID identity.

## Run from source without bundling

```bash
swift run DexGate
```

## Recommended first tests

Use the included demo scripts:

```text
examples/suspicious-demo.sh
examples/boring-demo.sh
```

For dependency audit testing, choose a script in `examples/` so DexGate also sees adjacent `package.json` and `requirements.txt`.
For DMG testing, choose a local `.dmg` that contains readable text files or manifests.

## Privacy model

DexGate reads the selected local file and optionally runs only local syntax/static tools. The app does not intentionally perform network requests.

Private audit bundles are written locally. Do not share a bundle if the script contains private paths, hostnames, internal names, credentials, or sensitive source code.

## Safety model

Use DexGate as the first gate:

1. Inspect metadata and hash.
2. Review risk score and category breakdown.
3. Review static findings.
4. Review danger map lines.
5. Review safer rewrite suggestions.
6. Review adjacent dependency manifests.
7. Run syntax-only static tools.
8. Export a private audit bundle if the result needs handoff or archive.
9. Generate a disposable no-network runner profile.
10. Execute only in a disposable no-network environment if execution is unavoidable.
11. Never run on the host if critical findings exist.

## Limitations

- Static pattern matching can miss malicious logic.
- Obfuscated scripts may require manual decoding.
- Dependency risk checks are useful but not complete supply-chain analysis.
- Docker Trace builds a local tracing image and may need network once to install tracing tools; traced script execution still uses `--network none`.
- Generated Docker commands are starting points, not guarantees.
- macOS-specific runtime behavior must be tested on macOS.
