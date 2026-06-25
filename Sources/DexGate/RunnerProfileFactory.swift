import Foundation

enum RunnerProfileFactory {
    static func make(for report: AnalysisReport) -> [RunnerProfile] {
        let sourcePath = shellQuote(report.fileURL.path)
        let fileName = shellQuote(report.fileName)
        let envFileName = fileName

        let prepare = """
mkdir -p dexgate-audit-in dexgate-audit-out
cp \(sourcePath) dexgate-audit-in/\(fileName)
chmod a-x dexgate-audit-in/\(fileName)
"""

        let syntax = """
\(prepare)
file dexgate-audit-in/\(fileName)
shasum -a 256 dexgate-audit-in/\(fileName)
sed -n '1,120p' dexgate-audit-in/\(fileName)

# Syntax-only checks. These do not run the script normally.
if command -v bash >/dev/null 2>&1; then bash -n dexgate-audit-in/\(fileName) 2>dexgate-audit-out/bash-n.txt || cat dexgate-audit-out/bash-n.txt; fi
if command -v zsh >/dev/null 2>&1; then zsh -n dexgate-audit-in/\(fileName) 2>dexgate-audit-out/zsh-n.txt || cat dexgate-audit-out/zsh-n.txt; fi
if command -v python3 >/dev/null 2>&1; then python3 -m py_compile dexgate-audit-in/\(fileName) 2>dexgate-audit-out/python-pycompile.txt || cat dexgate-audit-out/python-pycompile.txt; fi
if command -v node >/dev/null 2>&1; then node --check dexgate-audit-in/\(fileName) 2>dexgate-audit-out/node-check.txt || cat dexgate-audit-out/node-check.txt; fi
if command -v shellcheck >/dev/null 2>&1; then shellcheck dexgate-audit-in/\(fileName) 2>dexgate-audit-out/shellcheck.txt || cat dexgate-audit-out/shellcheck.txt; fi
"""

        let dockerInspect = """
\(prepare)

docker run --rm -it \\
  --network none \\
  --read-only \\
  --cap-drop ALL \\
  --security-opt no-new-privileges \\
  --pids-limit 128 \\
  --memory 512m \\
  --cpus 1 \\
  --mount type=bind,src="$PWD/dexgate-audit-in",dst=/in,readonly \\
  --mount type=bind,src="$PWD/dexgate-audit-out",dst=/out \\
  --env DEXGATE_FILE=\(envFileName) \\
  ubuntu:24.04 bash -lc 'cd /in && file "./$DEXGATE_FILE" && sha256sum "./$DEXGATE_FILE" && bash -n "./$DEXGATE_FILE" 2>/out/bash-n.txt || cat /out/bash-n.txt; sed -n "1,260p" "./$DEXGATE_FILE"'
"""

        let tempFolderReview = """
tmp="$(mktemp -d /tmp/dexgate.XXXXXX)"
mkdir -p "$tmp/out"
cp \(sourcePath) "$tmp"/\(fileName)
chmod a-x "$tmp"/\(fileName)
cd "$tmp"
file ./\(fileName)
shasum -a 256 ./\(fileName)
sed -n '1,260p' ./\(fileName)
# This profile is for host-side review only. Do not execute the script here.
printf 'Review folder: %s\\n' "$tmp"
"""

        let dockerDryRun = """
\(prepare)

docker run --rm -it \\
  --network none \\
  --cap-drop ALL \\
  --security-opt no-new-privileges \\
  --pids-limit 128 \\
  --memory 512m \\
  --cpus 1 \\
  --mount type=bind,src="$PWD/dexgate-audit-in",dst=/in,readonly \\
  --mount type=bind,src="$PWD/dexgate-audit-out",dst=/out \\
  --env DEXGATE_FILE=\(envFileName) \\
  ubuntu:24.04 bash -lc 'set -x; cd /tmp; mkdir -p dexgate-home dexgate-work; export HOME=/tmp/dexgate-home; cd dexgate-work; bash -x "/in/$DEXGATE_FILE" > /out/execution.stdout.txt 2> /out/execution.stderr.txt; printf "exit=$?\\n" > /out/exit-code.txt'
"""

        let dockerTrace = """
\(prepare)

# Build the tracing image first. The build step may need network once to install strace.
# Script execution below still uses --network none.
docker build -t dexgate-trace-ubuntu - <<'DOCKERFILE'
FROM ubuntu:24.04
RUN apt-get update && apt-get install -y --no-install-recommends strace file bash coreutils ca-certificates && rm -rf /var/lib/apt/lists/*
DOCKERFILE

docker run --rm -it \\
  --network none \\
  --cap-drop ALL \\
  --security-opt no-new-privileges \\
  --pids-limit 128 \\
  --memory 512m \\
  --cpus 1 \\
  --mount type=bind,src="$PWD/dexgate-audit-in",dst=/in,readonly \\
  --mount type=bind,src="$PWD/dexgate-audit-out",dst=/out \\
  --env DEXGATE_FILE=\(envFileName) \\
  dexgate-trace-ubuntu bash -lc 'cd /tmp; mkdir -p dexgate-home dexgate-work; export HOME=/tmp/dexgate-home; cd dexgate-work; strace -f -o /out/trace.log bash -x "/in/$DEXGATE_FILE" > /out/trace.stdout.txt 2> /out/trace.stderr.txt; printf "exit=$?\\n" > /out/trace-exit-code.txt; grep -E "connect|openat|unlink|rename|chmod|chown|execve|mount|setuid|setgid" /out/trace.log > /out/interesting-events.txt || true'
"""

        let bundle = """
# Use DexGate's "Export Private Audit Bundle" button for a complete evidence package.
# Bundle contents include: original script copy, Markdown report, findings JSON,
# dependency findings JSON, risk-score JSON, rewrite suggestions JSON,
# local tool output JSON, runner profile commands, and CHECKSUMS.sha256.
"""

        return [
            RunnerProfile(id: "syntax", title: "Syntax Only", safetyLevel: "Lowest blast radius", description: "Copies the script, removes execute bits, hashes it, previews it, and runs syntax-only checks where local tools exist.", command: syntax, executesScript: false),
            RunnerProfile(id: "docker-inspect", title: "Docker Inspect", safetyLevel: "No network / read-only input", description: "Runs file/hash/syntax/preview inside a no-network container with dropped capabilities, read-only root, and read-only script input.", command: dockerInspect, executesScript: false),
            RunnerProfile(id: "temp-review", title: "Temp Folder Review", safetyLevel: "Host review / no execution", description: "Copies the script to a fresh temp folder with execute bits removed for manual inspection. This is less isolated than Docker but convenient for quick review.", command: tempFolderReview, executesScript: false),
            RunnerProfile(id: "docker-dry-run", title: "Docker Dry Run", safetyLevel: "Contained execution", description: "Runs the script inside a no-network container with a fake HOME and temp workdir. Use only after manual review.", command: dockerDryRun, executesScript: true),
            RunnerProfile(id: "docker-trace", title: "Docker Trace", safetyLevel: "Contained execution with syscall log", description: "Builds a local strace image, then executes inside a no-network container and records file/process/network-related syscalls.", command: dockerTrace, executesScript: true),
            RunnerProfile(id: "bundle", title: "Audit Bundle", safetyLevel: "Evidence capture", description: "Use the GUI export button to save a private local bundle for handoff, archive, or review.", command: bundle, executesScript: false)
        ]
    }

    private static func shellQuote(_ value: String) -> String {
        "'" + value.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }
}
