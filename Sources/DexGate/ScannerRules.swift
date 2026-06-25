import Foundation

enum ScannerRules {
    static let rules: [AuditRule] = [
        AuditRule(
            id: "NET-001",
            title: "Remote download command",
            pattern: #"\b(curl|wget|Invoke-WebRequest|iwr)\b"#,
            severity: .high,
            category: .network,
            explanation: "The script may fetch remote content. Remote payloads can change after review.",
            recommendation: "Verify every URL, pin versions/checksums, and avoid piping remote content into an interpreter."
        ),
        AuditRule(
            id: "NET-002",
            title: "Direct TCP or netcat-style networking",
            pattern: #"(/dev/tcp|\bnc\b|\bncat\b|\bsocat\b|\btelnet\b)"#,
            severity: .high,
            category: .network,
            explanation: "The script may open direct network connections or transfer data outside normal package tooling.",
            recommendation: "Confirm the endpoint and purpose. Block network during sandbox testing unless it is essential."
        ),
        AuditRule(
            id: "NET-003",
            title: "URL found",
            pattern: #"https?://[^\s'\")]+"#,
            severity: .medium,
            category: .network,
            explanation: "A URL appears in the script. It may be benign, but remote dependencies deserve review.",
            recommendation: "Open the URL only if necessary, verify the domain, and require checksums for downloaded artifacts."
        ),
        AuditRule(
            id: "EXEC-001",
            title: "Remote or dynamic shell execution pattern",
            pattern: #"(bash\s+-c|sh\s+-c|zsh\s+-c|python\s+-c|python3\s+-c|perl\s+-e|ruby\s+-e|node\s+-e|eval\b|\bexec\b)"#,
            severity: .high,
            category: .shellExecution,
            explanation: "Dynamic execution makes the real command harder to inspect and can hide payload construction.",
            recommendation: "Expand the command into static code and inspect the exact arguments before running."
        ),
        AuditRule(
            id: "EXEC-002",
            title: "Pipe into shell/interpreter",
            pattern: #"\|\s*(bash|sh|zsh|python|python3|perl|ruby|node)\b"#,
            severity: .critical,
            category: .shellExecution,
            explanation: "Piping data directly into an interpreter can execute unreviewed content.",
            recommendation: "Download to a file, hash it, inspect it, then run only inside containment if still needed."
        ),
        AuditRule(
            id: "EXEC-003",
            title: "Command substitution",
            pattern: #"(\$\(|`[^`]+`)"#,
            severity: .medium,
            category: .shellExecution,
            explanation: "Command substitution can construct commands or arguments dynamically.",
            recommendation: "Trace the substitution value and verify it cannot be attacker-controlled."
        ),
        AuditRule(
            id: "OBF-001",
            title: "Base64 or encoding tool",
            pattern: #"\b(base64|xxd|openssl\s+enc|rot13|atob|btoa|fromCharCode)\b"#,
            severity: .high,
            category: .obfuscation,
            explanation: "Encoding/decoding can be legitimate, but it is also commonly used to hide commands.",
            recommendation: "Decode any embedded payload into a separate file and inspect it before execution."
        ),
        AuditRule(
            id: "PRIV-001",
            title: "Privilege escalation command",
            pattern: #"\b(sudo|su\s+|doas|pkexec)\b"#,
            severity: .high,
            category: .privilege,
            explanation: "The script may ask for elevated privileges. That expands the blast radius.",
            recommendation: "Require a precise explanation for every elevated command. Do not grant admin rights by default."
        ),
        AuditRule(
            id: "FS-001",
            title: "Broad destructive file operation",
            pattern: #"\brm\s+(-[A-Za-z]*r[A-Za-z]*f|-rf|-fr)\b|\bfind\b.*\b-delete\b|\bdd\s+if=|\bmkfs\b|\bdiskutil\b.*\b(erase|partition|apfs|delete)\b"#,
            severity: .critical,
            category: .destructive,
            explanation: "The script can delete, overwrite, or repartition data.",
            recommendation: "Do not run on host. If testing is unavoidable, use a disposable VM with no mounted host folders."
        ),
        AuditRule(
            id: "FS-002",
            title: "Permission or ownership change",
            pattern: #"\b(chmod|chown|chgrp|chattr|setfacl)\b"#,
            severity: .medium,
            category: .systemConfig,
            explanation: "Permission changes can make files executable, expose secrets, or break system behavior.",
            recommendation: "Verify the exact target path and avoid recursive changes unless narrowly scoped."
        ),
        AuditRule(
            id: "PERSIST-001",
            title: "Persistence mechanism",
            pattern: #"\b(crontab|launchctl|systemctl|service\s+|rc\.local|LoginItems|LaunchAgents|LaunchDaemons)\b"#,
            severity: .critical,
            category: .persistence,
            explanation: "The script may install something that survives after the script exits or after reboot.",
            recommendation: "Treat persistence as hostile until proven otherwise. Require a rollback command and inspect created files."
        ),
        AuditRule(
            id: "CRED-001",
            title: "Credential or secret path/reference",
            pattern: #"(~?/\.ssh|id_rsa|id_ed25519|authorized_keys|known_hosts|\.env\b|AWS_|GITHUB_TOKEN|OPENAI_API_KEY|ANTHROPIC_API_KEY|password|passwd|token|secret|keychain|security\s+)"#,
            severity: .critical,
            category: .credentials,
            explanation: "The script references credentials, key material, environment secrets, or macOS Keychain tooling.",
            recommendation: "Do not run on your main account. Review why credential access is needed and test with fake credentials only."
        ),
        AuditRule(
            id: "MAC-001",
            title: "AppleScript or macOS automation",
            pattern: #"\b(osascript|AppleScript|NSAppleEventsUsageDescription)\b"#,
            severity: .high,
            category: .privacy,
            explanation: "AppleScript can automate apps, read UI state, or trigger sensitive macOS permissions.",
            recommendation: "Inspect the target application and every AppleScript command before running."
        ),
        AuditRule(
            id: "MAC-002",
            title: "macOS defaults or plist modification",
            pattern: #"\b(defaults\s+write|plutil|/Library/Launch|~/Library/Launch|/etc/hosts|/etc/sudoers)\b"#,
            severity: .high,
            category: .systemConfig,
            explanation: "The script may modify system, launch, preference, hosts, or sudoer configuration.",
            recommendation: "Require a backup and exact rollback. Avoid running unless you understand every changed key/file."
        ),
        AuditRule(
            id: "DEP-001",
            title: "Package installation command",
            pattern: #"\b(pip3?\s+install|npm\s+(install|ci)|pnpm\s+install|yarn\s+(install|add)|brew\s+install|cargo\s+install|go\s+install|gem\s+install|composer\s+install)\b"#,
            severity: .medium,
            category: .dependency,
            explanation: "Package installation can fetch code and run dependency hooks.",
            recommendation: "Use lockfiles, pinned versions, ignore lifecycle scripts where possible, and prefer local/offline mirrors."
        ),
        AuditRule(
            id: "REMOTE-001",
            title: "Remote access or file transfer command",
            pattern: #"\b(ssh|scp|rsync|ftp|sftp)\b"#,
            severity: .medium,
            category: .network,
            explanation: "The script may access remote machines or transfer files.",
            recommendation: "Verify hostnames, identity files, and source/destination paths. Do not expose private keys to test runs."
        )
    ]
}
