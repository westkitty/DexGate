import Foundation

struct AuditRule: Identifiable, Hashable {
    let id: String
    let title: String
    let pattern: String
    let severity: FindingSeverity
    let category: FindingCategory
    let explanation: String
    let recommendation: String
}

enum FindingSeverity: String, CaseIterable, Comparable, Codable, Hashable {
    case info = "Info"
    case low = "Low"
    case medium = "Medium"
    case high = "High"
    case critical = "Critical"

    var rank: Int {
        switch self {
        case .info: return 0
        case .low: return 1
        case .medium: return 2
        case .high: return 3
        case .critical: return 4
        }
    }

    static func < (lhs: FindingSeverity, rhs: FindingSeverity) -> Bool {
        lhs.rank < rhs.rank
    }
}

enum FindingCategory: String, CaseIterable, Codable, Hashable {
    case network = "Network"
    case obfuscation = "Obfuscation"
    case privilege = "Privilege"
    case destructive = "Destructive"
    case persistence = "Persistence"
    case credentials = "Credentials"
    case dependency = "Dependency"
    case shellExecution = "Shell Execution"
    case systemConfig = "System Config"
    case privacy = "Privacy"
    case syntax = "Syntax"
    case other = "Other"
}

struct Finding: Identifiable, Hashable, Codable {
    let id: UUID
    let ruleID: String
    let title: String
    let severity: FindingSeverity
    let category: FindingCategory
    let lineNumber: Int
    let linePreview: String
    let explanation: String
    let recommendation: String
    let points: Int

    init(ruleID: String, title: String, severity: FindingSeverity, category: FindingCategory, lineNumber: Int, linePreview: String, explanation: String, recommendation: String, points: Int) {
        self.id = UUID()
        self.ruleID = ruleID
        self.title = title
        self.severity = severity
        self.category = category
        self.lineNumber = lineNumber
        self.linePreview = linePreview
        self.explanation = explanation
        self.recommendation = recommendation
        self.points = points
    }
}

struct DependencyFinding: Identifiable, Hashable, Codable {
    let id: UUID
    let fileName: String
    let severity: FindingSeverity
    let category: FindingCategory
    let title: String
    let detail: String
    let recommendation: String
    let points: Int

    init(fileName: String, severity: FindingSeverity, category: FindingCategory = .dependency, title: String, detail: String, recommendation: String, points: Int? = nil) {
        self.id = UUID()
        self.fileName = fileName
        self.severity = severity
        self.category = category
        self.title = title
        self.detail = detail
        self.recommendation = recommendation
        self.points = points ?? RiskScorer.points(for: severity, category: category, dependencyWeight: true)
    }
}

struct CommandResult: Identifiable, Hashable, Codable {
    let id: UUID
    let command: String
    let status: String
    let output: String

    init(command: String, status: String, output: String) {
        self.id = UUID()
        self.command = command
        self.status = status
        self.output = output
    }
}

enum RiskBand: String, Codable, Hashable {
    case quiet = "Quiet"
    case low = "Low"
    case guarded = "Guarded"
    case high = "High"
    case severe = "Severe"

    var explanation: String {
        switch self {
        case .quiet:
            return "No configured static tripwires fired. That is not proof of safety. It means DexGate did not find obvious patterns."
        case .low:
            return "Minor findings exist. Review them, but no strong static blocker was detected."
        case .guarded:
            return "Meaningful risk indicators exist. Manual review is required before any execution."
        case .high:
            return "High-risk behavior exists. Use containment only unless every finding is understood and justified."
        case .severe:
            return "Critical or clustered high-risk behavior exists. Do not run this on your host."
        }
    }
}

struct RiskCategoryBreakdown: Identifiable, Hashable, Codable {
    let id: UUID
    let category: FindingCategory
    let points: Int
    let findingCount: Int
    let highestSeverity: FindingSeverity
    let rationale: String

    init(category: FindingCategory, points: Int, findingCount: Int, highestSeverity: FindingSeverity, rationale: String) {
        self.id = UUID()
        self.category = category
        self.points = points
        self.findingCount = findingCount
        self.highestSeverity = highestSeverity
        self.rationale = rationale
    }
}

struct RiskScore: Hashable, Codable {
    let score: Int
    let rawPoints: Int
    let band: RiskBand
    let explanation: String
    let breakdown: [RiskCategoryBreakdown]
}

struct SafeRewriteSuggestion: Identifiable, Hashable, Codable {
    let id: UUID
    let sourceRuleID: String
    let lineNumber: Int?
    let title: String
    let original: String
    let saferPattern: String
    let explanation: String

    init(sourceRuleID: String, lineNumber: Int?, title: String, original: String, saferPattern: String, explanation: String) {
        self.id = UUID()
        self.sourceRuleID = sourceRuleID
        self.lineNumber = lineNumber
        self.title = title
        self.original = original
        self.saferPattern = saferPattern
        self.explanation = explanation
    }
}

struct RunnerProfile: Identifiable, Hashable, Codable {
    let id: String
    let title: String
    let safetyLevel: String
    let description: String
    let command: String
    let executesScript: Bool
}

struct AnalysisReport {
    var fileURL: URL
    var fileName: String
    var fileSizeDescription: String
    var sha256: String
    var interpreter: String
    var extensionType: String
    var lineCount: Int
    var readableText: String
    var findings: [Finding]
    var dependencyFindings: [DependencyFinding]
    var syntaxToolResults: [CommandResult]
    var riskScore: RiskScore
    var safeRewriteSuggestions: [SafeRewriteSuggestion]
    var generatedAt: Date

    var highestSeverity: FindingSeverity {
        let all = findings.map { $0.severity } + dependencyFindings.map { $0.severity }
        return all.max() ?? .info
    }

    var decision: SafetyDecision {
        if findings.contains(where: { $0.severity == .critical }) || dependencyFindings.contains(where: { $0.severity == .critical }) || riskScore.score >= 80 {
            return .blocked
        }
        if findings.contains(where: { $0.severity == .high }) || dependencyFindings.contains(where: { $0.severity == .high }) || riskScore.score >= 55 {
            return .containmentOnly
        }
        if findings.contains(where: { $0.severity == .medium }) || dependencyFindings.contains(where: { $0.severity == .medium }) || riskScore.score >= 25 {
            return .reviewRequired
        }
        if findings.isEmpty && dependencyFindings.isEmpty {
            return .unknownCleanStatic
        }
        return .lowRiskStatic
    }
}

enum SafetyDecision: String {
    case blocked = "Do not run on host"
    case containmentOnly = "Containment only"
    case reviewRequired = "Manual review required"
    case lowRiskStatic = "Low static risk"
    case unknownCleanStatic = "No static flags found"

    var explanation: String {
        switch self {
        case .blocked:
            return "Critical behavior or a severe risk score was detected. Treat this as unsafe for your real account and real machine."
        case .containmentOnly:
            return "High-risk behavior exists. Test only inside a disposable, no-network environment if execution is unavoidable."
        case .reviewRequired:
            return "The script has meaningful risk indicators. Read the matching lines before any execution."
        case .lowRiskStatic:
            return "Only low/info findings were detected. This still does not prove safety."
        case .unknownCleanStatic:
            return "No configured static pattern matched. This is not proof of safety. It means the obvious tripwires did not fire."
        }
    }
}

enum RiskScorer {
    static func points(for severity: FindingSeverity, category: FindingCategory, dependencyWeight: Bool = false) -> Int {
        let base: Double
        switch severity {
        case .info: base = 1
        case .low: base = 3
        case .medium: base = 8
        case .high: base = 18
        case .critical: base = 32
        }
        let multiplier: Double
        switch category {
        case .credentials, .destructive, .persistence:
            multiplier = 1.35
        case .shellExecution, .privilege, .obfuscation:
            multiplier = 1.15
        case .network, .systemConfig, .privacy:
            multiplier = 1.0
        case .dependency:
            multiplier = 0.9
        case .syntax, .other:
            multiplier = 0.7
        }
        let weight = dependencyWeight ? 0.75 : 1.0
        return max(1, Int((base * multiplier * weight).rounded()))
    }

    static func score(findings: [Finding], dependencyFindings: [DependencyFinding]) -> RiskScore {
        var categoryTotals: [FindingCategory: (points: Int, count: Int, highest: FindingSeverity)] = [:]

        for finding in findings {
            let current = categoryTotals[finding.category] ?? (0, 0, .info)
            categoryTotals[finding.category] = (current.points + finding.points, current.count + 1, max(current.highest, finding.severity))
        }
        for finding in dependencyFindings {
            let current = categoryTotals[finding.category] ?? (0, 0, .info)
            categoryTotals[finding.category] = (current.points + finding.points, current.count + 1, max(current.highest, finding.severity))
        }

        let rawPoints = categoryTotals.values.map { $0.points }.reduce(0, +)
        let capped = min(100, rawPoints)
        let band: RiskBand
        if capped == 0 {
            band = .quiet
        } else if capped <= 14 {
            band = .low
        } else if capped <= 34 {
            band = .guarded
        } else if capped <= 69 {
            band = .high
        } else {
            band = .severe
        }

        let breakdown = categoryTotals.map { key, value in
            RiskCategoryBreakdown(
                category: key,
                points: value.points,
                findingCount: value.count,
                highestSeverity: value.highest,
                rationale: "\(value.count) finding(s), highest severity \(value.highest.rawValue)."
            )
        }.sorted { left, right in
            if left.points != right.points { return left.points > right.points }
            return left.category.rawValue < right.category.rawValue
        }

        return RiskScore(
            score: capped,
            rawPoints: rawPoints,
            band: band,
            explanation: band.explanation,
            breakdown: breakdown
        )
    }
}
