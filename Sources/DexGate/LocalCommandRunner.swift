import Foundation

enum LocalCommandRunner {
    static func runStaticTools(for url: URL, interpreter: String) -> [CommandResult] {
        var commands: [[String]] = []
        let path = url.path
        let lower = url.lastPathComponent.lowercased()

        if lower.hasSuffix(".sh") || lower.hasSuffix(".bash") || interpreter.localizedCaseInsensitiveContains("bash") || interpreter == "shell" {
            commands.append(["/bin/bash", "-n", path])
        }
        if lower.hasSuffix(".zsh") || interpreter.localizedCaseInsensitiveContains("zsh") {
            commands.append(["/bin/zsh", "-n", path])
        }
        if lower.hasSuffix(".py") || interpreter.localizedCaseInsensitiveContains("python") {
            commands.append(["/usr/bin/python3", "-m", "py_compile", path])
        }
        if lower.hasSuffix(".js") || lower.hasSuffix(".mjs") || lower.hasSuffix(".cjs") || interpreter.localizedCaseInsensitiveContains("node") {
            if let node = which("node") {
                commands.append([node, "--check", path])
            }
        }
        if let shellcheck = which("shellcheck"), lower.hasSuffix(".sh") || lower.hasSuffix(".bash") || interpreter.localizedCaseInsensitiveContains("bash") || interpreter == "shell" {
            commands.append([shellcheck, path])
        }

        if commands.isEmpty {
            return [CommandResult(command: "No local static syntax tool selected", status: "Skipped", output: "DexGate did not find a matching local syntax-only command for this file type.")]
        }

        return commands.map { run(command: $0) }
    }

    private static func which(_ executable: String) -> String? {
        let result = run(command: ["/usr/bin/env", "which", executable])
        if result.status == "0" {
            let path = result.output.trimmingCharacters(in: .whitespacesAndNewlines)
            return path.isEmpty ? nil : path
        }
        return nil
    }

    private static func run(command: [String]) -> CommandResult {
        let process = Process()
        let out = Pipe()
        let err = Pipe()
        process.executableURL = URL(fileURLWithPath: command[0])
        process.arguments = Array(command.dropFirst())
        process.standardOutput = out
        process.standardError = err

        do {
            try process.run()
            process.waitUntilExit()
            let stdout = String(data: out.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
            let stderr = String(data: err.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
            let output = [stdout, stderr].filter { !$0.isEmpty }.joined(separator: "\n")
            return CommandResult(command: shellQuoted(command), status: String(process.terminationStatus), output: output.isEmpty ? "No output." : output)
        } catch {
            return CommandResult(command: shellQuoted(command), status: "Error", output: error.localizedDescription)
        }
    }

    private static func shellQuoted(_ parts: [String]) -> String {
        parts.map { part in
            if part.rangeOfCharacter(from: CharacterSet.alphanumerics.inverted) == nil { return part }
            return "'" + part.replacingOccurrences(of: "'", with: "'\\''") + "'"
        }.joined(separator: " ")
    }
}
