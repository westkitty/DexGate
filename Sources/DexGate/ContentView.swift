import AppKit
import Foundation
import SwiftUI
import UniformTypeIdentifiers

struct ContentView: View {
    @StateObject private var model = AppViewModel()
    @State private var isDropTargeted = false
    @State private var selectedRunnerProfileIndex = 0

    var body: some View {
        VStack(spacing: 0) {
            header
            Divider()
            HStack(spacing: 0) {
                sidebar
                    .frame(width: 340)
                Divider()
                mainPanel
            }
        }
        .alert("DexGate", isPresented: .constant(model.errorMessage != nil), actions: {
            Button("OK") { model.errorMessage = nil }
        }, message: {
            Text(model.errorMessage ?? "")
        })
    }

    private var header: some View {
        HStack(alignment: .center) {
            VStack(alignment: .leading, spacing: 4) {
                Text("DexGate")
                    .font(.largeTitle.bold())
                Text("Private local script inspection. No uploads. No hidden execution. Gate first, regret never.")
                    .foregroundStyle(.secondary)
            }
            Spacer()
            if model.isAnalyzing {
                ProgressView()
                    .controlSize(.small)
                Text("Analyzing locally...")
                    .foregroundStyle(.secondary)
            }
        }
        .padding(20)
    }

    private var sidebar: some View {
        VStack(alignment: .leading, spacing: 16) {
            dropZone

            Button {
                model.chooseScriptFile()
            } label: {
                Label("Choose Script", systemImage: "doc.badge.plus")
                    .frame(maxWidth: .infinity)
            }
            .controlSize(.large)

            Button {
                model.analyzeSelected(includeLocalTools: false)
            } label: {
                Label("Analyze", systemImage: "magnifyingglass")
                    .frame(maxWidth: .infinity)
            }
            .controlSize(.large)
            .disabled(model.selectedURL == nil || model.isAnalyzing)

            Button {
                model.analyzeSelected(includeLocalTools: true)
            } label: {
                Label("Run Local Static Tools", systemImage: "terminal")
                    .frame(maxWidth: .infinity)
            }
            .help("Runs syntax-only local checks such as bash -n, zsh -n, python -m py_compile, node --check, and shellcheck if installed. It does not run the script normally.")
            .disabled(model.selectedURL == nil || model.isAnalyzing)

            Button {
                model.exportMarkdownReport()
            } label: {
                Label("Export Markdown Report", systemImage: "square.and.arrow.down")
                    .frame(maxWidth: .infinity)
            }
            .disabled(model.report == nil)

            Button {
                model.exportPrivateBundle()
            } label: {
                Label("Export Private Audit Bundle", systemImage: "archivebox")
                    .frame(maxWidth: .infinity)
            }
            .disabled(model.report == nil)

            Divider()

            GroupBox("Offline lock") {
                VStack(alignment: .leading, spacing: 8) {
                    Toggle("Network features disabled", isOn: $model.offlineLockEnabled)
                        .disabled(true)
                    Label("DexGate has no upload/scanner client", systemImage: "wifi.slash")
                    Label("Generated Docker profiles use --network none", systemImage: "lock.shield")
                    Label("Local tool runs are syntax/static only", systemImage: "terminal")
                }
                .font(.callout)
                .foregroundStyle(.secondary)
                .frame(maxWidth: .infinity, alignment: .leading)
            }

            Spacer()
        }
        .padding(18)
    }

    private var dropZone: some View {
        VStack(spacing: 10) {
            Image(systemName: "shield.lefthalf.filled.badge.checkmark")
                .font(.system(size: 42))
                .foregroundStyle(isDropTargeted ? .primary : .secondary)
            Text(model.selectedURL?.lastPathComponent ?? "Drop a script here")
                .font(.headline)
                .multilineTextAlignment(.center)
            Text("Shell, Python, Node, Ruby, Perl, .command, or any text script")
                .font(.caption)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
        }
        .frame(maxWidth: .infinity, minHeight: 170)
        .padding()
        .background(
            RoundedRectangle(cornerRadius: 18)
                .fill(isDropTargeted ? Color.accentColor.opacity(0.14) : Color.secondary.opacity(0.08))
        )
        .overlay(
            RoundedRectangle(cornerRadius: 18)
                .strokeBorder(isDropTargeted ? Color.accentColor : Color.secondary.opacity(0.25), style: StrokeStyle(lineWidth: 2, dash: [8, 5]))
        )
        .onDrop(of: [UTType.fileURL.identifier], isTargeted: $isDropTargeted) { providers in
            model.handleDrop(providers: providers)
        }
    }

    @ViewBuilder
    private var mainPanel: some View {
        if let report = model.report {
            VStack(spacing: 0) {
                summaryStrip(report)
                Divider()
                TabView {
                    summaryTab(report)
                        .tabItem { Label("Summary", systemImage: "gauge.with.dots.needle.67percent") }
                    riskScoreTab(report)
                        .tabItem { Label("Risk Score", systemImage: "speedometer") }
                    findingsTab(report)
                        .tabItem { Label("Findings", systemImage: "exclamationmark.triangle") }
                    dangerMapTab(report)
                        .tabItem { Label("Danger Map", systemImage: "text.viewfinder") }
                    rewritesTab(report)
                        .tabItem { Label("Rewrites", systemImage: "wand.and.stars") }
                    dependencyTab(report)
                        .tabItem { Label("Dependencies", systemImage: "shippingbox") }
                    containmentTab(report)
                        .tabItem { Label("Runner Profiles", systemImage: "lock.shield") }
                    toolsTab(report)
                        .tabItem { Label("Tool Output", systemImage: "terminal") }
                }
                .padding(12)
            }
        } else {
            VStack(spacing: 16) {
                Image(systemName: "shield.checkered")
                    .font(.system(size: 72))
                    .foregroundStyle(.secondary)
                Text("Choose or drop a script to inspect it locally.")
                    .font(.title2.bold())
                Text("DexGate scores risk, highlights dangerous lines, suggests safer rewrites, audits nearby dependency manifests, enforces offline-first behavior, generates disposable runner profiles including trace mode, and exports private audit bundles. It still cannot prove safety. Nothing can. Annoying, but true.")
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .frame(maxWidth: 720)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            .padding()
        }
    }

    private func summaryStrip(_ report: AnalysisReport) -> some View {
        HStack(spacing: 12) {
            summaryCard(title: "Decision", value: report.decision.rawValue, detail: report.decision.explanation)
            summaryCard(title: "Risk Score", value: "\(report.riskScore.score)/100", detail: "\(report.riskScore.band.rawValue): \(report.riskScore.explanation)")
            summaryCard(title: "Findings", value: "\(report.findings.count)", detail: "Script pattern matches")
            summaryCard(title: "Dependencies", value: "\(report.dependencyFindings.count)", detail: "Adjacent project signals")
        }
        .padding(14)
    }

    private func summaryCard(title: String, value: String, detail: String) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(title)
                .font(.caption)
                .foregroundStyle(.secondary)
            Text(value)
                .font(.headline)
                .lineLimit(2)
            Text(detail)
                .font(.caption)
                .foregroundStyle(.secondary)
                .lineLimit(4)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(12)
        .background(RoundedRectangle(cornerRadius: 12).fill(Color.secondary.opacity(0.08)))
    }

    private func summaryTab(_ report: AnalysisReport) -> some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                GroupBox("Selected file") {
                    Grid(alignment: .leading, horizontalSpacing: 18, verticalSpacing: 8) {
                        gridRow("Name", report.fileName)
                        gridRow("Path", report.fileURL.path)
                        gridRow("Size", report.fileSizeDescription)
                        gridRow("SHA-256", report.sha256)
                        gridRow("Interpreter", report.interpreter)
                        gridRow("Extension", report.extensionType)
                        gridRow("Line count", "\(report.lineCount)")
                        gridRow("Offline mode", model.offlineLockEnabled ? "Enforced" : "Unexpectedly disabled")
                    }
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
                }

                GroupBox("Decision logic") {
                    VStack(alignment: .leading, spacing: 8) {
                        Text(report.decision.rawValue)
                            .font(.title3.bold())
                        Text(report.decision.explanation)
                        Text("Risk score: \(report.riskScore.score)/100. \(report.riskScore.explanation)")
                        Text("DexGate reports static risk. It cannot certify a script as safe. Final approval still requires human review, dependency inspection, and contained testing.")
                            .foregroundStyle(.secondary)
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                }
            }
            .padding()
        }
    }

    private func riskScoreTab(_ report: AnalysisReport) -> some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                HStack(alignment: .firstTextBaseline, spacing: 12) {
                    Text("\(report.riskScore.score)")
                        .font(.system(size: 56, weight: .bold, design: .rounded))
                    Text("/100")
                        .font(.title2.bold())
                        .foregroundStyle(.secondary)
                    VStack(alignment: .leading) {
                        Text(report.riskScore.band.rawValue)
                            .font(.title2.bold())
                        Text(report.riskScore.explanation)
                            .foregroundStyle(.secondary)
                    }
                }

                ProgressView(value: Double(report.riskScore.score), total: 100)
                    .controlSize(.large)

                Text("Raw points: \(report.riskScore.rawPoints). The visible score is capped at 100. Categories such as credentials, destructive operations, and persistence carry heavier weight because the blast radius is larger.")
                    .foregroundStyle(.secondary)

                if report.riskScore.breakdown.isEmpty {
                    EmptyStateView(title: "No category points", systemImage: "checkmark.seal", message: "No configured static finding contributed to the risk score.")
                } else {
                    ForEach(report.riskScore.breakdown) { item in
                        HStack(alignment: .top, spacing: 12) {
                            Text("\(item.points)")
                                .font(.title3.bold())
                                .frame(width: 52, alignment: .trailing)
                            VStack(alignment: .leading, spacing: 4) {
                                Text(item.category.rawValue)
                                    .font(.headline)
                                Text(item.rationale)
                                    .foregroundStyle(.secondary)
                            }
                            Spacer()
                            Text(item.highestSeverity.rawValue)
                                .font(.caption.bold())
                                .padding(.horizontal, 8)
                                .padding(.vertical, 3)
                                .background(Capsule().fill(severityColor(item.highestSeverity).opacity(0.18)))
                        }
                        .padding()
                        .background(RoundedRectangle(cornerRadius: 12).fill(Color.secondary.opacity(0.08)))
                    }
                }
            }
            .padding()
        }
    }

    private func findingsTab(_ report: AnalysisReport) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            if report.findings.isEmpty {
                EmptyStateView(title: "No configured static findings", systemImage: "checkmark.seal", message: "No obvious tripwire matched. This is not proof of safety.")
            } else {
                List(report.findings) { finding in
                    VStack(alignment: .leading, spacing: 6) {
                        HStack {
                            severityBadge(finding.severity)
                            Text(finding.category.rawValue)
                                .font(.caption)
                                .foregroundStyle(.secondary)
                            Text("Line \(finding.lineNumber)")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                            Text("+\(finding.points) pts")
                                .font(.caption.monospaced())
                                .foregroundStyle(.secondary)
                            Spacer()
                            Text(finding.ruleID)
                                .font(.caption.monospaced())
                                .foregroundStyle(.secondary)
                        }
                        Text(finding.title)
                            .font(.headline)
                        Text(finding.linePreview)
                            .font(.system(.body, design: .monospaced))
                            .textSelection(.enabled)
                        Text(finding.explanation)
                        Text("Recommendation: \(finding.recommendation)")
                            .foregroundStyle(.secondary)
                    }
                    .padding(.vertical, 6)
                }
            }
        }
    }

    private func dangerMapTab(_ report: AnalysisReport) -> some View {
        let lines = report.readableText.components(separatedBy: .newlines)
        let grouped = Dictionary(grouping: report.findings, by: { $0.lineNumber })
        return VStack(alignment: .leading, spacing: 8) {
            Text("Danger map")
                .font(.headline)
            Text("Read-only script view with risky lines highlighted. Click a finding in the list when you need the full explanation; this view is for scanning the shape of danger quickly.")
                .font(.caption)
                .foregroundStyle(.secondary)
            ScrollView {
                LazyVStack(alignment: .leading, spacing: 0) {
                    ForEach(Array(lines.enumerated()), id: \.offset) { item in
                        let lineNumber = item.offset + 1
                        let line = item.element
                        let matches = grouped[lineNumber] ?? []
                        dangerLine(lineNumber: lineNumber, line: line, matches: matches)
                    }
                }
                .padding(.vertical, 6)
            }
            .background(RoundedRectangle(cornerRadius: 12).fill(Color.secondary.opacity(0.08)))
        }
        .padding()
    }

    private func dangerLine(lineNumber: Int, line: String, matches: [Finding]) -> some View {
        let highest = matches.map { $0.severity }.max()
        return HStack(alignment: .top, spacing: 10) {
            Text(String(format: "%4d", lineNumber))
                .font(.system(.caption, design: .monospaced))
                .foregroundStyle(.secondary)
                .frame(width: 48, alignment: .trailing)
            Text(matches.isEmpty ? " " : "!")
                .font(.system(.caption, design: .monospaced).bold())
                .foregroundStyle(highest.map { severityColor($0) } ?? Color.secondary)
                .frame(width: 14)
            Text(line.isEmpty ? " " : line)
                .font(.system(.body, design: .monospaced))
                .textSelection(.enabled)
                .frame(maxWidth: .infinity, alignment: .leading)
            if !matches.isEmpty {
                Text(matches.map { $0.ruleID }.joined(separator: ", "))
                    .font(.caption.monospaced())
                    .foregroundStyle(.secondary)
            }
        }
        .padding(.horizontal, 8)
        .padding(.vertical, 3)
        .background((highest.map { severityColor($0).opacity(0.15) }) ?? Color.clear)
    }

    private func rewritesTab(_ report: AnalysisReport) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            if report.safeRewriteSuggestions.isEmpty {
                EmptyStateView(title: "No rewrite suggestions", systemImage: "wand.and.stars", message: "DexGate did not detect a configured pattern with a specific safer rewrite. That is not a safety certificate.")
            } else {
                List(report.safeRewriteSuggestions) { suggestion in
                    VStack(alignment: .leading, spacing: 8) {
                        HStack {
                            Text(suggestion.sourceRuleID)
                                .font(.caption.monospaced())
                                .foregroundStyle(.secondary)
                            if let line = suggestion.lineNumber {
                                Text("Line \(line)")
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            }
                            Spacer()
                            Button("Copy Safer Pattern") {
                                copyToClipboard(suggestion.saferPattern)
                            }
                        }
                        Text(suggestion.title)
                            .font(.headline)
                        Text("Original / trigger")
                            .font(.caption.bold())
                            .foregroundStyle(.secondary)
                        codeBlock(suggestion.original)
                        Text("Safer pattern")
                            .font(.caption.bold())
                            .foregroundStyle(.secondary)
                        codeBlock(suggestion.saferPattern)
                        Text(suggestion.explanation)
                            .foregroundStyle(.secondary)
                    }
                    .padding(.vertical, 8)
                }
            }
        }
    }

    private func dependencyTab(_ report: AnalysisReport) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            if report.dependencyFindings.isEmpty {
                EmptyStateView(title: "No adjacent dependency files found", systemImage: "tray", message: "DexGate checked the selected file's directory for common dependency and project files.")
            } else {
                List(report.dependencyFindings) { finding in
                    VStack(alignment: .leading, spacing: 6) {
                        HStack {
                            severityBadge(finding.severity)
                            Text(finding.fileName)
                                .font(.caption.monospaced())
                                .foregroundStyle(.secondary)
                            Text("+\(finding.points) pts")
                                .font(.caption.monospaced())
                                .foregroundStyle(.secondary)
                        }
                        Text(finding.title)
                            .font(.headline)
                        Text(finding.detail)
                            .textSelection(.enabled)
                        Text("Recommendation: \(finding.recommendation)")
                            .foregroundStyle(.secondary)
                    }
                    .padding(.vertical, 6)
                }
            }
        }
    }

    private func containmentTab(_ report: AnalysisReport) -> some View {
        let profiles = RunnerProfileFactory.make(for: report)
        let selectedIndex = min(selectedRunnerProfileIndex, max(0, profiles.count - 1))
        let profile = profiles[selectedIndex]
        return ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                Text("Disposable runner profiles")
                    .font(.title2.bold())
                Text("DexGate generates commands only. Review them before Terminal gets involved. Especially the profiles marked as contained execution.")
                    .foregroundStyle(.secondary)

                Picker("Profile", selection: $selectedRunnerProfileIndex) {
                    ForEach(Array(profiles.enumerated()), id: \.offset) { index, item in
                        Text(item.title).tag(index)
                    }
                }
                .pickerStyle(.segmented)

                GroupBox(profile.title) {
                    VStack(alignment: .leading, spacing: 8) {
                        HStack {
                            Text(profile.safetyLevel)
                                .font(.caption.bold())
                                .padding(.horizontal, 8)
                                .padding(.vertical, 3)
                                .background(Capsule().fill(profile.executesScript ? Color.orange.opacity(0.18) : Color.blue.opacity(0.18)))
                            Text(profile.executesScript ? "May execute inside containment" : "No normal script execution")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                            Spacer()
                            Button("Copy Command") {
                                copyToClipboard(profile.command)
                            }
                        }
                        Text(profile.description)
                        codeBlock(profile.command)
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.vertical, 4)
                }

                Text("Host execution gate")
                    .font(.headline)
                VStack(alignment: .leading, spacing: 6) {
                    Text("Do not run on host if any Critical finding exists.")
                    Text("Use containment only for High findings unless you fully understand the behavior.")
                    Text("Never run with sudo until every elevated command has a narrow reason and rollback.")
                    Text("Never run dependency installs with lifecycle scripts enabled during first review.")
                }
            }
            .padding()
        }
    }

    private func toolsTab(_ report: AnalysisReport) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            if report.syntaxToolResults.isEmpty {
                EmptyStateView(title: "Local static tools not run", systemImage: "terminal", message: "Use the sidebar button to run syntax-only local checks.")
            } else {
                List(report.syntaxToolResults) { result in
                    VStack(alignment: .leading, spacing: 6) {
                        HStack {
                            Text("Exit: \(result.status)")
                                .font(.caption.bold())
                            Text(result.command)
                                .font(.caption.monospaced())
                                .foregroundStyle(.secondary)
                        }
                        Text(result.output)
                            .font(.system(.body, design: .monospaced))
                            .textSelection(.enabled)
                    }
                    .padding(.vertical, 6)
                }
            }
        }
    }

    private func gridRow(_ key: String, _ value: String) -> some View {
        GridRow {
            Text(key)
                .foregroundStyle(.secondary)
            Text(value)
                .textSelection(.enabled)
        }
    }

    private func severityBadge(_ severity: FindingSeverity) -> some View {
        Text(severity.rawValue)
            .font(.caption.bold())
            .padding(.horizontal, 8)
            .padding(.vertical, 3)
            .background(Capsule().fill(severityColor(severity).opacity(0.18)))
    }

    private func codeBlock(_ text: String) -> some View {
        ScrollView(.horizontal) {
            Text(text)
                .font(.system(.body, design: .monospaced))
                .textSelection(.enabled)
                .padding()
        }
        .background(RoundedRectangle(cornerRadius: 12).fill(Color.secondary.opacity(0.08)))
    }

    private func severityColor(_ severity: FindingSeverity) -> Color {
        switch severity {
        case .critical: return .red
        case .high: return .orange
        case .medium: return .yellow
        case .low: return .blue
        case .info: return .gray
        }
    }

    private func copyToClipboard(_ value: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(value, forType: .string)
    }

    private func shellQuote(_ value: String) -> String {
        "'" + value.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }
}

@MainActor
final class AppViewModel: ObservableObject {
    @Published var selectedURL: URL?
    @Published var report: AnalysisReport?
    @Published var isAnalyzing = false
    @Published var errorMessage: String?
    @Published var offlineLockEnabled = true

    private let analyzer = ScriptAnalyzer()

    func chooseScriptFile() {
        let panel = NSOpenPanel()
        panel.title = "Choose a script to inspect"
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false
        panel.allowedContentTypes = [.item]
        if panel.runModal() == .OK, let url = panel.url {
            selectedURL = url
            analyzeSelected(includeLocalTools: false)
        }
    }

    func handleDrop(providers: [NSItemProvider]) -> Bool {
        guard let provider = providers.first else { return false }
        provider.loadItem(forTypeIdentifier: UTType.fileURL.identifier, options: nil) { item, error in
            if let error = error {
                Task { @MainActor in self.errorMessage = error.localizedDescription }
                return
            }
            var url: URL?
            if let data = item as? Data, let string = String(data: data, encoding: .utf8) {
                url = URL(string: string)
            } else if let nsURL = item as? NSURL {
                url = nsURL as URL
            } else if let string = item as? String {
                url = URL(string: string)
            }
            if let url {
                Task { @MainActor in
                    self.selectedURL = url
                    self.analyzeSelected(includeLocalTools: false)
                }
            }
        }
        return true
    }

    func analyzeSelected(includeLocalTools: Bool) {
        guard let selectedURL else { return }
        isAnalyzing = true
        Task {
            let newReport = await analyzer.analyze(url: selectedURL, includeLocalToolResults: includeLocalTools)
            await MainActor.run {
                self.report = newReport
                self.isAnalyzing = false
            }
        }
    }

    func exportMarkdownReport() {
        guard let report else { return }
        let panel = NSSavePanel()
        panel.title = "Export DexGate report"
        panel.nameFieldStringValue = "DexGate-\(safeFileStem(report.fileName))-report.md"
        if let markdownType = UTType(filenameExtension: "md") {
            panel.allowedContentTypes = [markdownType]
        }
        if panel.runModal() == .OK, let url = panel.url {
            do {
                try markdown(for: report).write(to: url, atomically: true, encoding: .utf8)
            } catch {
                errorMessage = error.localizedDescription
            }
        }
    }

    func exportPrivateBundle() {
        guard let report else { return }
        let panel = NSOpenPanel()
        panel.title = "Choose a folder for the DexGate private audit bundle"
        panel.prompt = "Export Bundle"
        panel.canChooseFiles = false
        panel.canChooseDirectories = true
        panel.canCreateDirectories = true
        panel.allowsMultipleSelection = false
        if panel.runModal() == .OK, let folder = panel.url {
            do {
                let bundleURL = folder.appendingPathComponent("DexGate-\(safeFileStem(report.fileName))-audit-\(timestamp())", isDirectory: true)
                try writeBundle(for: report, to: bundleURL)
            } catch {
                errorMessage = error.localizedDescription
            }
        }
    }

    private func writeBundle(for report: AnalysisReport, to bundleURL: URL) throws {
        let fm = FileManager.default
        try fm.createDirectory(at: bundleURL, withIntermediateDirectories: true)
        let originals = bundleURL.appendingPathComponent("originals", isDirectory: true)
        let qa = bundleURL.appendingPathComponent("qa", isDirectory: true)
        let commands = bundleURL.appendingPathComponent("commands", isDirectory: true)
        try fm.createDirectory(at: originals, withIntermediateDirectories: true)
        try fm.createDirectory(at: qa, withIntermediateDirectories: true)
        try fm.createDirectory(at: commands, withIntermediateDirectories: true)

        let originalCopy = originals.appendingPathComponent(report.fileName)
        if fm.fileExists(atPath: originalCopy.path) { try fm.removeItem(at: originalCopy) }
        try fm.copyItem(at: report.fileURL, to: originalCopy)

        try markdown(for: report).write(to: bundleURL.appendingPathComponent("DexGate-report.md"), atomically: true, encoding: .utf8)
        try jsonData(report.findings).write(to: qa.appendingPathComponent("findings.json"))
        try jsonData(report.dependencyFindings).write(to: qa.appendingPathComponent("dependency-findings.json"))
        try jsonData(report.riskScore).write(to: qa.appendingPathComponent("risk-score.json"))
        try jsonData(report.safeRewriteSuggestions).write(to: qa.appendingPathComponent("rewrite-suggestions.json"))
        try jsonData(report.syntaxToolResults).write(to: qa.appendingPathComponent("local-tool-results.json"))

        let profiles = RunnerProfileFactory.make(for: report)
        let profileScript = profiles.map { profile in
            "# MARK: \(profile.title)\n# \(profile.description)\n\n\(profile.command)\n"
        }.joined(separator: "\n\n")
        try profileScript.write(to: commands.appendingPathComponent("runner-profiles.sh"), atomically: true, encoding: .utf8)
        try jsonData(profiles).write(to: qa.appendingPathComponent("runner-profiles.json"))

        let manifest = """
# DexGate Private Audit Bundle

- Generated: \(Date())
- Original file: \(report.fileName)
- SHA-256: \(report.sha256)
- Decision: \(report.decision.rawValue)
- Risk score: \(report.riskScore.score)/100 (\(report.riskScore.band.rawValue))
- Offline lock: enforced

## Contents

- `originals/\(report.fileName)` - copied original script
- `DexGate-report.md` - human-readable report
- `qa/findings.json` - static finding data
- `qa/dependency-findings.json` - dependency manifest findings
- `qa/risk-score.json` - explainable risk score
- `qa/rewrite-suggestions.json` - safer rewrite suggestions
- `qa/local-tool-results.json` - syntax/static tool output if run
- `commands/runner-profiles.sh` - disposable test commands
- `CHECKSUMS.sha256` - bundle file checksums

No upload was performed by DexGate. Keep this bundle private if the script contains paths, hostnames, credentials, or internal context.
"""
        try manifest.write(to: bundleURL.appendingPathComponent("README.md"), atomically: true, encoding: .utf8)
        try writeChecksums(for: bundleURL)
    }

    private func writeChecksums(for bundleURL: URL) throws {
        let fm = FileManager.default
        guard let enumerator = fm.enumerator(at: bundleURL, includingPropertiesForKeys: [.isRegularFileKey], options: [.skipsHiddenFiles]) else { return }
        var lines: [String] = []
        for case let fileURL as URL in enumerator {
            if fileURL.lastPathComponent == "CHECKSUMS.sha256" { continue }
            let values = try fileURL.resourceValues(forKeys: [.isRegularFileKey])
            guard values.isRegularFile == true else { continue }
            let data = try Data(contentsOf: fileURL)
            let sha = ScriptAnalyzer.sha256(data: data)
            let rel = fileURL.path.replacingOccurrences(of: bundleURL.path + "/", with: "")
            lines.append("\(sha)  \(rel)")
        }
        try lines.sorted().joined(separator: "\n").appending("\n").write(to: bundleURL.appendingPathComponent("CHECKSUMS.sha256"), atomically: true, encoding: .utf8)
    }

    private func jsonData<T: Encodable>(_ value: T) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        encoder.dateEncodingStrategy = .iso8601
        return try encoder.encode(value)
    }

    private func markdown(for report: AnalysisReport) -> String {
        var out = """
# DexGate Report: \(report.fileName)

Generated: \(report.generatedAt)

## Decision

**\(report.decision.rawValue)**  
\(report.decision.explanation)

## Risk Score

- Score: \(report.riskScore.score)/100
- Raw points: \(report.riskScore.rawPoints)
- Band: \(report.riskScore.band.rawValue)
- Explanation: \(report.riskScore.explanation)

"""
        if report.riskScore.breakdown.isEmpty {
            out += "No configured category points.\n\n"
        } else {
            out += "| Category | Points | Count | Highest | Rationale |\n|---|---:|---:|---|---|\n"
            for item in report.riskScore.breakdown {
                out += "| \(item.category.rawValue) | \(item.points) | \(item.findingCount) | \(item.highestSeverity.rawValue) | \(item.rationale) |\n"
            }
            out += "\n"
        }

        out += """
## File

- Path: `\(report.fileURL.path)`
- Size: \(report.fileSizeDescription)
- SHA-256: `\(report.sha256)`
- Interpreter: `\(report.interpreter)`
- Extension: `\(report.extensionType)`
- Lines inspected: \(report.lineCount)
- Offline lock: enforced

## Findings

"""
        if report.findings.isEmpty {
            out += "No configured static findings. This is not proof of safety.\n\n"
        } else {
            for finding in report.findings {
                out += """
### [\(finding.severity.rawValue)] \(finding.title)

- Rule: `\(finding.ruleID)`
- Category: \(finding.category.rawValue)
- Points: \(finding.points)
- Line: \(finding.lineNumber)
- Evidence: `\(finding.linePreview.replacingOccurrences(of: "`", with: "'"))`
- Why it matters: \(finding.explanation)
- Recommendation: \(finding.recommendation)

"""
            }
        }

        out += "## Dependency Context\n\n"
        if report.dependencyFindings.isEmpty {
            out += "No adjacent dependency/project files were found by the checker.\n\n"
        } else {
            for finding in report.dependencyFindings {
                out += """
### [\(finding.severity.rawValue)] \(finding.title)

- File: `\(finding.fileName)`
- Points: \(finding.points)
- Detail: \(finding.detail)
- Recommendation: \(finding.recommendation)

"""
            }
        }

        out += "## Safer Rewrite Suggestions\n\n"
        if report.safeRewriteSuggestions.isEmpty {
            out += "No configured rewrite suggestions were generated.\n\n"
        } else {
            for suggestion in report.safeRewriteSuggestions {
                out += """
### \(suggestion.title)

- Source rule: `\(suggestion.sourceRuleID)`
- Line: \(suggestion.lineNumber == nil ? "n/a" : String(suggestion.lineNumber!))
- Trigger: `\(suggestion.original.replacingOccurrences(of: "`", with: "'"))`
- Why: \(suggestion.explanation)

```bash
\(suggestion.saferPattern)
```

"""
            }
        }

        out += "## Local Static Tool Output\n\n"
        if report.syntaxToolResults.isEmpty {
            out += "Local static tools were not run.\n\n"
        } else {
            for result in report.syntaxToolResults {
                out += """
### `\(result.command)`

Exit/status: `\(result.status)`

```text
\(result.output)
```

"""
            }
        }

        out += """
## Safety Note

DexGate performs local static inspection. It cannot certify a script as safe. Do not run scripts on your real host/account until static review, dependency review, and contained testing are complete.
"""
        return out
    }

    private func safeFileStem(_ value: String) -> String {
        let allowed = CharacterSet.alphanumerics.union(CharacterSet(charactersIn: "-_."))
        let filtered = value.unicodeScalars.map { allowed.contains($0) ? Character($0) : "-" }
        return String(filtered).isEmpty ? "script" : String(filtered)
    }

    private func timestamp() -> String {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyyMMdd-HHmmss"
        return formatter.string(from: Date())
    }

    private func shellQuote(_ value: String) -> String {
        "'" + value.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }
}

struct EmptyStateView: View {
    let title: String
    let systemImage: String
    let message: String

    var body: some View {
        VStack(spacing: 12) {
            Image(systemName: systemImage)
                .font(.system(size: 48))
                .foregroundStyle(.secondary)
            Text(title)
                .font(.title3.bold())
            Text(message)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .frame(maxWidth: 560)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .padding()
    }
}
