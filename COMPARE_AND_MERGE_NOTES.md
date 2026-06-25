# DexGate 0.3.0 Compare and Merge Notes

## Compared inputs

- `DexGate-0.2.0-source.zip` — previous generated version.
- `DexGate-0.2.0-source(2).zip` — user-supplied alternate version.

## Summary verdict

The user-supplied alternate version had the stronger foundation: cleaner risk scoring, richer dependency checks, better private bundle export, compile-friendly conditional CryptoKit handling, and QA logs. The previous generated version had better feature coverage for runner profiles and included dependency-audit fixtures that were useful for testing.

DexGate 0.3.0 uses the alternate version as the base and merges in the better missing elements from the previous version.

## What the previous generated version did better

| Area | Better element kept |
|---|---|
| Runner profile coverage | Included explicit temp-folder and trace-style containment concepts. |
| Test fixtures | Included `examples/package.json` and `examples/requirements.txt` for dependency audit testing. |
| Release notes | More explicit about not being compiled/notarized in this environment. |
| Offline framing | More explicit that network safety is a policy surface, not just a label. |

## What the uploaded alternate version did better

| Area | Better element kept |
|---|---|
| Risk score | Stronger point-based scorer with category multipliers and risk bands. |
| Dependency audit | Much deeper checks across npm, Python, Rust, Go, Ruby, Make, Docker/compose/task files. |
| Safe rewrites | More structured rewrite suggestions with generated examples. |
| Private bundle | Stronger bundle export with JSON evidence, checksums, and README. |
| Build portability | Conditional CryptoKit import allowed non-UI Swift core parsing in this Linux runtime. |
| QA evidence | Included preflight/core-parse/build-attempt logs. |
| UI completeness | Better tab structure and clearer summary/risk/danger map flow. |

## Optimal 0.3.0 changes

- Added `RunnerProfileFactory.swift` so runner commands are generated in one place instead of duplicated in `ContentView` and `AppViewModel`.
- Expanded runner profiles to six profiles:
  - Syntax Only
  - Docker Inspect
  - Temp Folder Review
  - Docker Dry Run
  - Docker Trace
  - Audit Bundle guidance
- Preserved the uploaded version's stronger risk scorer, dependency scanner, private bundle export, and UI flow.
- Restored dependency-audit fixtures: `examples/package.json` and `examples/requirements.txt`.
- Updated docs, release notes, manifest, Codex prompt, and build version to 0.3.0.

## Not changed deliberately

- No cloud scanner support.
- No VirusTotal integration.
- No AI/API upload behavior.
- No automatic host execution of selected scripts.
- No Developer ID signing or notarization claims.

## Remaining validation gap

This runtime is Linux. Native macOS SwiftUI/AppKit compilation, GUI launch, app signing verification, and bundle launch testing must happen on macOS.
