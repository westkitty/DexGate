import Foundation
#if canImport(CryptoKit)
import CryptoKit
#endif

final class ScriptAnalyzer {
    private let maxReadBytes = 2_000_000

    func analyze(url: URL, includeLocalToolResults: Bool = false) async -> AnalysisReport {
        let access = url.startAccessingSecurityScopedResource()
        defer {
            if access { url.stopAccessingSecurityScopedResource() }
        }

        let fileName = url.lastPathComponent
        let data = (try? Data(contentsOf: url, options: [.mappedIfSafe])) ?? Data()
        let limitedData = Data(data.prefix(maxReadBytes))
        let text = String(data: limitedData, encoding: .utf8)
            ?? String(data: limitedData, encoding: .ascii)
            ?? "[DexGate could not decode this file as UTF-8 or ASCII text.]"
        let sha = Self.sha256(data: data)
        let lineCount = text.split(whereSeparator: \.isNewline).count
        let interpreter = Self.detectInterpreter(fileName: fileName, text: text)
        let ext = url.pathExtension.isEmpty ? "none" : url.pathExtension.lowercased()
        let findings = scanText(text)
        let dependencyFindings = scanAdjacentDependencies(for: url)
        let riskScore = RiskScorer.score(findings: findings, dependencyFindings: dependencyFindings)
        let suggestions = Self.buildRewriteSuggestions(findings: findings, dependencyFindings: dependencyFindings)
        let syntaxToolResults: [CommandResult]
        if includeLocalToolResults {
            syntaxToolResults = LocalCommandRunner.runStaticTools(for: url, interpreter: interpreter)
        } else {
            syntaxToolResults = []
        }

        return AnalysisReport(
            fileURL: url,
            fileName: fileName,
            fileSizeDescription: ByteCountFormatter.string(fromByteCount: Int64(data.count), countStyle: .file),
            sha256: sha,
            interpreter: interpreter,
            extensionType: ext,
            lineCount: lineCount,
            readableText: text,
            findings: findings,
            dependencyFindings: dependencyFindings,
            syntaxToolResults: syntaxToolResults,
            riskScore: riskScore,
            safeRewriteSuggestions: suggestions,
            generatedAt: Date()
        )
    }

    private func scanText(_ text: String) -> [Finding] {
        let lines = text.components(separatedBy: .newlines)
        var findings: [Finding] = []

        for rule in ScannerRules.rules {
            guard let regex = try? NSRegularExpression(pattern: rule.pattern, options: [.caseInsensitive]) else { continue }
            for (index, line) in lines.enumerated() {
                let range = NSRange(location: 0, length: (line as NSString).length)
                if regex.firstMatch(in: line, options: [], range: range) != nil {
                    let points = RiskScorer.points(for: rule.severity, category: rule.category)
                    findings.append(
                        Finding(
                            ruleID: rule.id,
                            title: rule.title,
                            severity: rule.severity,
                            category: rule.category,
                            lineNumber: index + 1,
                            linePreview: Self.trim(line, limit: 240),
                            explanation: rule.explanation,
                            recommendation: rule.recommendation,
                            points: points
                        )
                    )
                }
            }
        }

        return findings.sorted { left, right in
            if left.severity != right.severity { return left.severity > right.severity }
            if left.lineNumber != right.lineNumber { return left.lineNumber < right.lineNumber }
            return left.ruleID < right.ruleID
        }
    }

    private func scanAdjacentDependencies(for url: URL) -> [DependencyFinding] {
        let directory = url.hasDirectoryPath ? url : url.deletingLastPathComponent()
        var results: [DependencyFinding] = []
        let manager = FileManager.default

        func fileExists(_ name: String) -> URL? {
            let candidate = directory.appendingPathComponent(name)
            return manager.fileExists(atPath: candidate.path) ? candidate : nil
        }

        if let package = fileExists("package.json") {
            results.append(contentsOf: inspectPackageJSON(package))
        }

        for lockName in ["package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml"] {
            if fileExists(lockName) != nil {
                results.append(DependencyFinding(
                    fileName: lockName,
                    severity: .info,
                    title: "Node lockfile present",
                    detail: "A Node package manager lockfile was found next to the selected script.",
                    recommendation: "Prefer lockfile-based installs with lifecycle scripts disabled during review."
                ))
            }
        }

        if let npmrc = fileExists(".npmrc") {
            results.append(contentsOf: inspectTextManifest(npmrc, fileName: ".npmrc", checks: [
                ManifestCheck(pattern: #"ignore-scripts\s*=\s*false"#, severity: .high, title: "npm scripts explicitly enabled", detail: "The npm config appears to enable lifecycle scripts.", recommendation: "Set ignore-scripts=true during review installs."),
                ManifestCheck(pattern: #"registry\s*=\s*https?://"#, severity: .medium, title: "Custom npm registry", detail: "A custom registry is configured.", recommendation: "Verify the registry owner and dependency confusion protections."),
                ManifestCheck(pattern: #"_authToken|//.*:_authToken"#, severity: .critical, title: "npm auth token reference", detail: "The npm config references an auth token.", recommendation: "Do not include real tokens in audit bundles. Rotate exposed tokens if necessary.")
            ]))
        }

        if let requirements = fileExists("requirements.txt") {
            results.append(contentsOf: inspectRequirements(requirements))
        }

        if let pyproject = fileExists("pyproject.toml") {
            results.append(contentsOf: inspectTextManifest(pyproject, fileName: "pyproject.toml", checks: [
                ManifestCheck(pattern: #"\[build-system\]"#, severity: .low, title: "Python build system found", detail: "pyproject.toml declares build metadata.", recommendation: "Inspect build-backend and build requirements before package installation."),
                ManifestCheck(pattern: #"dependencies\s*=\s*\["#, severity: .low, title: "Python dependency list found", detail: "pyproject.toml includes dependencies.", recommendation: "Review dependency pinning and run pip-audit locally."),
                ManifestCheck(pattern: #"(http://|https://|git\+)"#, severity: .medium, title: "Remote Python dependency reference", detail: "pyproject.toml references a remote URL or git dependency.", recommendation: "Prefer pinned versions and verified hashes from trusted indexes."
                )
            ]))
        }

        if let setup = fileExists("setup.py") {
            results.append(DependencyFinding(
                fileName: "setup.py",
                severity: .high,
                title: "Executable Python packaging script",
                detail: "setup.py is code, not just metadata, and can execute during packaging workflows.",
                recommendation: "Read setup.py before running pip install, build, or editable installs."
            ))
            results.append(contentsOf: inspectTextManifest(setup, fileName: "setup.py", checks: [
                ManifestCheck(pattern: #"os\.system|subprocess|eval\(|exec\("#, severity: .high, title: "setup.py executes commands", detail: "setup.py appears to spawn commands or evaluate dynamic code.", recommendation: "Do not run packaging commands until these calls are justified.")
            ]))
        }

        if let cargo = fileExists("Cargo.toml") {
            results.append(contentsOf: inspectTextManifest(cargo, fileName: "Cargo.toml", checks: [
                ManifestCheck(pattern: #"git\s*="#, severity: .medium, title: "Cargo git dependency", detail: "Cargo.toml references a git dependency.", recommendation: "Pin the revision and inspect the dependency source."),
                ManifestCheck(pattern: #"path\s*="#, severity: .low, title: "Cargo path dependency", detail: "Cargo.toml references a local path dependency.", recommendation: "Inspect the local dependency before building.")
            ]))
        }

        if let goMod = fileExists("go.mod") {
            results.append(contentsOf: inspectTextManifest(goMod, fileName: "go.mod", checks: [
                ManifestCheck(pattern: #"^replace\s+"#, severity: .medium, title: "Go replace directive", detail: "go.mod contains a replace directive.", recommendation: "Verify replacement paths and modules before building."),
                ManifestCheck(pattern: #"v0\.0\.0|latest"#, severity: .low, title: "Loose Go module version", detail: "go.mod may reference a loose or placeholder version.", recommendation: "Pin module versions for reproducible review.")
            ]))
        }

        if let gemfile = fileExists("Gemfile") {
            results.append(contentsOf: inspectTextManifest(gemfile, fileName: "Gemfile", checks: [
                ManifestCheck(pattern: #"git:\s*['\"]|github:\s*['\"]|http://|https://"#, severity: .medium, title: "Remote Ruby dependency", detail: "Gemfile references a remote git/http dependency.", recommendation: "Pin revisions and inspect the dependency before bundle install."),
                ManifestCheck(pattern: #"gem\s+['\"][^'\"]+['\"]\s*$"#, severity: .low, title: "Unpinned Ruby dependency", detail: "Gemfile may include an unpinned gem dependency.", recommendation: "Prefer pinned versions for repeatable review.")
            ]))
        }

        if let makefile = fileExists("Makefile") {
            results.append(contentsOf: inspectTextManifest(makefile, fileName: "Makefile", checks: [
                ManifestCheck(pattern: #"curl|wget|sudo|rm\s+-rf|npm\s+install|pip\s+install"#, severity: .medium, title: "Makefile contains risky command", detail: "The Makefile includes commands that may download, install, elevate, or delete.", recommendation: "Inspect every target before running make."
                )
            ]))
        }

        for name in ["Pipfile", "poetry.lock", "requirements-dev.txt", "justfile", "Taskfile.yml", "Dockerfile", "docker-compose.yml", "compose.yml"] {
            if fileExists(name) != nil {
                results.append(DependencyFinding(
                    fileName: name,
                    severity: .low,
                    title: "Adjacent project/dependency file found",
                    detail: "\(name) exists in the same directory as the selected script.",
                    recommendation: "Inspect this file before assuming the selected script is self-contained."
                ))
            }
        }

        return results.sorted { left, right in
            if left.severity != right.severity { return left.severity > right.severity }
            if left.fileName != right.fileName { return left.fileName < right.fileName }
            return left.title < right.title
        }
    }

    private struct ManifestCheck {
        let pattern: String
        let severity: FindingSeverity
        let title: String
        let detail: String
        let recommendation: String
    }

    private func inspectTextManifest(_ url: URL, fileName: String, checks: [ManifestCheck]) -> [DependencyFinding] {
        let text = (try? String(contentsOf: url, encoding: .utf8)) ?? ""
        var results: [DependencyFinding] = []
        for check in checks {
            if text.range(of: check.pattern, options: [.regularExpression, .caseInsensitive]) != nil {
                results.append(DependencyFinding(
                    fileName: fileName,
                    severity: check.severity,
                    title: check.title,
                    detail: check.detail,
                    recommendation: check.recommendation
                ))
            }
        }
        if results.isEmpty {
            results.append(DependencyFinding(
                fileName: fileName,
                severity: .info,
                title: "Manifest inspected",
                detail: "DexGate found \(fileName) and did not match its configured high-risk manifest checks.",
                recommendation: "Still inspect the file manually before running dependency commands."
            ))
        }
        return results
    }

    private func inspectRequirements(_ url: URL) -> [DependencyFinding] {
        let text = (try? String(contentsOf: url, encoding: .utf8)) ?? ""
        var results: [DependencyFinding] = []
        let activeLines = text.components(separatedBy: .newlines).map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }.filter { !$0.isEmpty && !$0.hasPrefix("#") }

        let unpinned = activeLines.filter { line in
            !line.contains("==") && !line.contains("===") && !line.contains("@ file://") && !line.hasPrefix("--")
        }
        if !unpinned.isEmpty {
            results.append(DependencyFinding(
                fileName: "requirements.txt",
                severity: .medium,
                title: "Unpinned Python requirements",
                detail: "Some Python dependencies are not pinned with exact versions: \(unpinned.prefix(8).joined(separator: ", "))",
                recommendation: "Pin versions, use hashes for serious review, and install in a disposable virtual environment."
            ))
        }

        let remote = activeLines.filter { $0.contains("git+") || $0.contains("http://") || $0.contains("https://") }
        if !remote.isEmpty {
            results.append(DependencyFinding(
                fileName: "requirements.txt",
                severity: .high,
                title: "Remote Python dependency reference",
                detail: "requirements.txt references git or URL dependencies: \(remote.prefix(6).joined(separator: ", "))",
                recommendation: "Pin commit hashes, verify source, and avoid installing until reviewed."
            ))
        }

        let indexFlags = activeLines.filter { $0.contains("--extra-index-url") || $0.contains("--index-url") || $0.contains("--trusted-host") }
        if !indexFlags.isEmpty {
            results.append(DependencyFinding(
                fileName: "requirements.txt",
                severity: .high,
                title: "Custom Python package index",
                detail: "requirements.txt configures an index/trusted host: \(indexFlags.prefix(6).joined(separator: ", "))",
                recommendation: "Check dependency-confusion exposure and prefer --no-index with a local wheelhouse during review."
            ))
        }

        let editable = activeLines.filter { $0.hasPrefix("-e ") || $0.hasPrefix("--editable") }
        if !editable.isEmpty {
            results.append(DependencyFinding(
                fileName: "requirements.txt",
                severity: .medium,
                title: "Editable Python install",
                detail: "requirements.txt includes editable installs: \(editable.prefix(6).joined(separator: ", "))",
                recommendation: "Inspect editable package paths and setup hooks before installing."
            ))
        }

        if results.isEmpty {
            results.append(DependencyFinding(
                fileName: "requirements.txt",
                severity: .info,
                title: "Python requirements found",
                detail: "No obvious unpinned, remote, editable, or custom-index lines were detected by the simple checker.",
                recommendation: "Still run pip-audit locally and inspect transitive dependencies before execution."
            ))
        }

        return results
    }

    private func inspectPackageJSON(_ url: URL) -> [DependencyFinding] {
        var results: [DependencyFinding] = []
        guard let data = try? Data(contentsOf: url),
              let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            return [DependencyFinding(
                fileName: "package.json",
                severity: .medium,
                title: "Could not parse package.json",
                detail: "package.json exists but could not be parsed as JSON.",
                recommendation: "Inspect it manually before running npm, pnpm, yarn, or node commands."
            )]
        }

        if let scripts = object["scripts"] as? [String: Any] {
            let dangerousNames = ["preinstall", "install", "postinstall", "prepare", "prepack", "postpack", "prepublish", "prepublishOnly"]
            let found = dangerousNames.compactMap { key -> String? in
                if let value = scripts[key] as? String { return "\(key): \(Self.trim(value, limit: 160))" }
                return nil
            }
            if !found.isEmpty {
                results.append(DependencyFinding(
                    fileName: "package.json",
                    severity: .high,
                    title: "Node install lifecycle scripts",
                    detail: found.joined(separator: " | "),
                    recommendation: "Use npm install --ignore-scripts or npm ci --ignore-scripts until each hook is reviewed."
                ))
            }

            let riskyScripts = scripts.compactMap { key, value -> String? in
                guard let command = value as? String else { return nil }
                if command.range(of: #"curl|wget|sudo|rm\s+-rf|node\s+-e|bash\s+-c|sh\s+-c"#, options: [.regularExpression, .caseInsensitive]) != nil {
                    return "\(key): \(Self.trim(command, limit: 140))"
                }
                return nil
            }
            if !riskyScripts.isEmpty {
                results.append(DependencyFinding(
                    fileName: "package.json",
                    severity: .high,
                    title: "Risky Node script command",
                    detail: riskyScripts.prefix(8).joined(separator: " | "),
                    recommendation: "Do not run npm scripts until these commands are reviewed line by line."
                ))
            }

            if found.isEmpty && riskyScripts.isEmpty {
                results.append(DependencyFinding(
                    fileName: "package.json",
                    severity: .info,
                    title: "package.json scripts inspected",
                    detail: "No common install lifecycle script names or configured risky command strings were found by the simple checker.",
                    recommendation: "Still inspect all scripts and package manager configuration before installing."
                ))
            }
        }

        for key in ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"] {
            if let deps = object[key] as? [String: Any], !deps.isEmpty {
                results.append(DependencyFinding(
                    fileName: "package.json",
                    severity: key == "optionalDependencies" ? .medium : .low,
                    title: "Node \(key) found",
                    detail: "\(key) count: \(deps.count)",
                    recommendation: "Prefer lockfile-based installs with scripts disabled during review."
                ))

                let suspiciousDeps = deps.compactMap { depName, depValue -> String? in
                    let value = String(describing: depValue)
                    if value == "latest" || value == "*" || value.hasPrefix("git+") || value.contains("github:") || value.contains("http://") || value.contains("https://") || value.hasPrefix("file:") {
                        return "\(depName): \(value)"
                    }
                    if value.hasPrefix("^") || value.hasPrefix("~") {
                        return "\(depName): \(value)"
                    }
                    return nil
                }
                if !suspiciousDeps.isEmpty {
                    results.append(DependencyFinding(
                        fileName: "package.json",
                        severity: .medium,
                        title: "Loose or remote Node dependency versions",
                        detail: suspiciousDeps.prefix(10).joined(separator: ", "),
                        recommendation: "Prefer exact versions, lockfiles, and verified source for first review."
                    ))
                }
            }
        }

        if let packageManager = object["packageManager"] as? String {
            results.append(DependencyFinding(
                fileName: "package.json",
                severity: .info,
                title: "Package manager declared",
                detail: packageManager,
                recommendation: "Use the declared package manager with scripts disabled during review."
            ))
        }

        return results
    }

    static func buildRewriteSuggestions(findings: [Finding], dependencyFindings: [DependencyFinding]) -> [SafeRewriteSuggestion] {
        var suggestions: [SafeRewriteSuggestion] = []
        var seen = Set<String>()

        for finding in findings {
            let key = "\(finding.ruleID)-\(finding.lineNumber)"
            guard !seen.contains(key) else { continue }
            seen.insert(key)
            suggestions.append(suggestion(for: finding))
        }

        for finding in dependencyFindings where finding.severity.rank >= FindingSeverity.medium.rank {
            let key = "DEP-\(finding.fileName)-\(finding.title)"
            guard !seen.contains(key) else { continue }
            seen.insert(key)
            suggestions.append(SafeRewriteSuggestion(
                sourceRuleID: "DEPENDENCY",
                lineNumber: nil,
                title: "Safer dependency handling: \(finding.fileName)",
                original: finding.detail,
                saferPattern: dependencySaferPattern(for: finding),
                explanation: finding.recommendation
            ))
        }

        return suggestions
    }

    private static func suggestion(for finding: Finding) -> SafeRewriteSuggestion {
        let safer: String
        let title: String
        switch finding.ruleID {
        case "EXEC-002":
            title = "Replace pipe-to-shell with inspect-then-run"
            safer = """
# Instead of: curl ... | bash
curl -fsSLO 'https://example.invalid/script.sh'
shasum -a 256 script.sh
less script.sh
bash -n script.sh
# Run only in containment if still required.
"""
        case "NET-001", "NET-003":
            title = "Pin and verify remote content"
            safer = """
url='https://example.invalid/artifact'
expected_sha256='PASTE_EXPECTED_HASH_HERE'
curl -fsSLO "$url"
actual_sha256="$(shasum -a 256 "${url##*/}" | awk '{print $1}')"
test "$actual_sha256" = "$expected_sha256"
"""
        case "PRIV-001":
            title = "Isolate privileged steps"
            safer = """
# Split privileged commands into a separate reviewed script.
# Require exact target paths and a rollback command before sudo.
printf '%s\n' 'Review privileged command here before running.'
"""
        case "FS-001":
            title = "Constrain destructive file operations"
            safer = """
target="/tmp/dexgate-review-target"
test -n "$target"
test "$target" != "/"
test "$target" = /tmp/dexgate-* || exit 1
rm -rf -- "$target"
"""
        case "PERSIST-001":
            title = "Make persistence explicit and reversible"
            safer = """
# Require a visible install path, label, and uninstall command.
# Example rollback must be tested before enabling persistence.
launchctl bootout gui/$(id -u) "$HOME/Library/LaunchAgents/example.plist"
rm -f "$HOME/Library/LaunchAgents/example.plist"
"""
        case "CRED-001":
            title = "Use fake credentials during review"
            safer = """
export AWS_ACCESS_KEY_ID='FAKE_FOR_REVIEW'
export AWS_SECRET_ACCESS_KEY='FAKE_FOR_REVIEW'
# Do not mount ~/.ssh, Keychain, browser profiles, or real .env files into test runs.
"""
        case "OBF-001":
            title = "Decode payloads into files before review"
            safer = """
# Decode to a separate file, inspect it, then analyze that decoded file too.
base64 --decode suspicious.b64 > decoded-payload.txt
less decoded-payload.txt
"""
        default:
            title = "Rewrite for narrower blast radius"
            safer = """
# Replace dynamic or broad behavior with explicit paths, pinned inputs,
# syntax-only checks, and a containment-first test command.
"""
        }

        return SafeRewriteSuggestion(
            sourceRuleID: finding.ruleID,
            lineNumber: finding.lineNumber,
            title: title,
            original: finding.linePreview,
            saferPattern: safer,
            explanation: finding.recommendation
        )
    }

    private static func dependencySaferPattern(for finding: DependencyFinding) -> String {
        switch finding.fileName {
        case "package.json", "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", ".npmrc":
            return """
npm ci --ignore-scripts
npm audit --omit=dev
npm pkg get scripts
# Enable scripts only after every lifecycle hook is reviewed.
"""
        case "requirements.txt", "pyproject.toml", "setup.py":
            return """
python3 -m venv .venv-review
. .venv-review/bin/activate
python -m pip install --upgrade pip
python -m pip install --no-index --find-links=/path/to/local/wheelhouse -r requirements.txt
pip-audit -r requirements.txt
"""
        default:
            return "Inspect the manifest manually, pin remote inputs, and run build/install commands only inside a disposable environment."
        }
    }

    static func sha256(data: Data) -> String {
        #if canImport(CryptoKit)
        let digest = SHA256.hash(data: data)
        return digest.map { String(format: "%02x", $0) }.joined()
        #else
        return "sha256-unavailable-outside-macos-cryptokit-build"
        #endif
    }

    static func detectInterpreter(fileName: String, text: String) -> String {
        if let first = text.components(separatedBy: .newlines).first, first.hasPrefix("#!") {
            return first.replacingOccurrences(of: "#!", with: "").trimmingCharacters(in: .whitespacesAndNewlines)
        }
        let lower = fileName.lowercased()
        if lower.hasSuffix(".sh") { return "shell" }
        if lower.hasSuffix(".zsh") { return "zsh" }
        if lower.hasSuffix(".bash") { return "bash" }
        if lower.hasSuffix(".py") { return "python" }
        if lower.hasSuffix(".js") || lower.hasSuffix(".mjs") || lower.hasSuffix(".cjs") { return "node" }
        if lower.hasSuffix(".rb") { return "ruby" }
        if lower.hasSuffix(".pl") { return "perl" }
        if lower.hasSuffix(".command") { return "macOS command script" }
        return "unknown"
    }

    static func trim(_ text: String, limit: Int) -> String {
        let clean = text.trimmingCharacters(in: .whitespacesAndNewlines)
        if clean.count <= limit { return clean }
        return String(clean.prefix(limit)) + "..."
    }
}
