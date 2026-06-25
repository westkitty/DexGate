# DexGate 0.3.0 Release Notes

## Type

Optimal source/handoff release for native macOS compile.

## Summary

DexGate 0.3.0 compares the prior generated 0.2.0 source bundle against the uploaded alternate 0.2.0 source bundle and merges the best pieces into one cleaner version.

## Major improvements

- Adopted the stronger point-based risk scoring model from the uploaded alternate version.
- Kept the richer dependency manifest auditing from the uploaded alternate version.
- Kept private audit bundle export with JSON evidence and checksums.
- Added `RunnerProfileFactory.swift` to remove duplicate runner profile generation.
- Expanded runner profiles to include:
  - Syntax Only
  - Docker Inspect
  - Temp Folder Review
  - Docker Dry Run
  - Docker Trace
  - Audit Bundle guidance
- Restored dependency audit fixtures:
  - `examples/package.json`
  - `examples/requirements.txt`
- Updated build metadata to `0.3.0`.
- Updated README, manifest, QA notes, and Codex build prompt.

## Build compatibility fixes

- Fixed a regex option mismatch in dependency manifest inspection.
- Replaced invalid SwiftUI alignment and save-panel content-type constants with macOS-compatible equivalents.
- Verified the package builds and the app bundle packages on macOS after those fixes.

## Preserved features

- Drag-and-drop script intake.
- Choose Script file picker.
- Local static pattern scanning.
- SHA-256 hashing on macOS through CryptoKit.
- Conditional non-macOS fallback so core Swift files can be parsed in Linux validation.
- Interpreter/shebang detection.
- Danger Map tab.
- Rewrites tab.
- Dependency tab.
- Offline lock UI.
- Optional syntax-only local tool checks.
- Markdown report export.
- No hidden host execution.

## Not included

- Compiled `.app` from this Linux runtime.
- Developer ID signing.
- Apple notarization.
- Cloud scanning or network submission.
- Automatic execution of uploaded scripts.

## Known limits

- Static scanner can miss malicious logic.
- Dependency audit is heuristic and should be followed by ecosystem-specific audit tools.
- Docker Trace builds a local tracing image and may need network once to install tracing tools; traced script execution still uses `--network none`.
- Native compile and GUI smoke testing must happen on macOS.
