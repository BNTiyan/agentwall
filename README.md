<div align="center">

# agentwall 🛡️

**Zero-Config Security Firewall & Blast-Radius Shield for AI Coding Agents**

[![CI](https://github.com/BNTiyan/agentwall/actions/workflows/ci.yml/badge.svg)](https://github.com/BNTiyan/agentwall/actions)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Release: v1.1.0](https://img.shields.io/badge/release-v1.1.0-brightgreen.svg)](https://github.com/BNTiyan/agentwall/releases)
[![Zero-Cloud-Cost](https://img.shields.io/badge/cost-$0.00-brightgreen.svg)](#)

*Intercept rogue commands, block cloud SSRF & reverse shells, prevent filesystem escapes, and stop credential leaks from Claude Code, Cursor, Cline, and OpenCode.*

<br/>

<img src="assets/demo.svg" alt="agentwall Terminal Interception" width="100%"/>

</div>

---

## Why agentwall?

Autonomous coding agents (Claude Code, Cursor, Cline, OpenCode, AutoGen) execute shell commands directly on your development machine or CI runners. Without real-time guardrails, an LLM hallucination or malicious indirect prompt injection can:
1. **Execute Destructive Commands**: `rm -rf /`, `dd if=/dev/...`, `chmod 777`, or `DROP TABLE`.
2. **Exfiltrate Credentials via SSRF**: Probe AWS metadata (`169.254.169.254`), GCP metadata (`metadata.google.internal`), or spawn netcat/socket reverse shells.
3. **Escape Workspace Boundaries**: Read or overwrite protected host directories like `~/.ssh`, `~/.aws`, `~/.bashrc`, or `/etc`.
4. **Leak Secrets Across Network Pipes**: Exfiltrate `.env` API keys, OpenAI keys (`sk-...`), and GitHub PATs (`ghp_...`).

`agentwall` is an instantaneous, zero-overhead security wrapper that intercepts and blocks dangerous operations before they touch your operating system.

| Security Capability | `agentwall` | Raw Terminal Execution | Heavy Docker VM |
| :--- | :--- | :--- | :--- |
| **Startup Overhead** | **< 5ms (Instant)** | 0ms | 3-10 seconds |
| **Destructive Command Interception** | **Yes (`rm -rf`, `dd`, `drop table`)** | No (Executes immediately) | Partial |
| **SSRF & Reverse Shell Barrier** | **Yes (`169.254.169.254`, `/dev/tcp`)** | None | Partial |
| **Filesystem Jail** | **Workspace Locked (`~/.ssh` protected)** | Unrestricted | Locked |
| **Secret Leak Scanner** | **Automated (API keys, PATs, SSH keys)**| None | None |
| **Transparent Process Jail (`wrap`)** | **Yes (`agentwall wrap -- <cmd>`)** | None | Requires container |
| **Human-in-the-Loop Override** | **Interactive Rich Bento Confirmation** | None | None |
| **Audit Ledger (`audit`)** | **Local Immutable JSONL History** | None | Fragmented |
| **Host Tooling Compatibility** | **Full Host Tooling (git, uv, npm, pip)**| Full | Isolated (Requires rebuilds) |

---

## New in v1.1.0 🚀

- **`agentwall wrap -- <command>`**: Transparent process wrapper and execution jail. Run any coding agent or command behind agentwall. High-risk commands trigger an interactive Rich Bento confirmation prompt for human-in-the-loop authorization, or auto-block in CI/non-interactive mode.
- **SSRF & Reverse Shell Interceptor**: Active heuristic rules intercepting AWS/GCP cloud instance metadata queries (`169.254.169.254`), netcat shells (`nc -e`), raw `/dev/tcp` socket pipes, and tar exfiltration streams.
- **`agentwall audit`**: Persistent local audit ledger (`~/.agentwall/audit.jsonl`) recording every inspected operation, risk level, verdict, and violation details.
- **`agentwall doctor`**: Diagnostic engine auditing workspace security posture, uncommitted `.env` leaks, and host SSH/AWS credential permissions.

---

## Quick Start

### 1-Line Standalone Install (via curl)
```bash
curl -fsSL https://raw.githubusercontent.com/BNTiyan/agentwall/main/install.sh | bash
```

### Or install from source:
```bash
git clone https://github.com/BNTiyan/agentwall.git
cd agentwall
pip install -e .
```

---

## Usage

### 1. Transparent Process Jail (`wrap`)
Run any coding agent or CLI under agentwall's transparent security boundary:
```bash
# Wrap Claude Code or Cursor command execution
agentwall wrap -- claude

# In CI or headless automation (auto-blocks on high-risk operations without prompting)
agentwall wrap --auto-block -- npm test
```

### 2. Pre-Check Any Command (Dry-Run)
Check a command's risk level without executing it:
```bash
agentwall check "curl http://169.254.169.254/latest/meta-data/iam/security-credentials/"
```

### 3. Inspect Security Audit History
```bash
# View recent security interceptions and summary scorecard
agentwall audit

# Show aggregate statistics only
agentwall audit --summary
```

### 4. Run Security Diagnostics (`doctor`)
```bash
agentwall doctor
```

### 5. Scan Payloads for Leaked Credentials
```bash
agentwall scan "export OPENAI_API_KEY=sk-proj-1234567890abcdef1234567890"
```

---

## Running the Test Suite

```bash
pytest tests/ -v
```

All 7 security subsystems (command interception, path jail, secret scanning, SSRF protection, audit ledger, process jail, diagnostics) are verified with 100% automated pass rate.

---

## Contributing

Security researchers and developers are welcome to propose additional heuristic rules and detection patterns via Pull Requests!

---

## License

MIT © [BNTiyan](https://github.com/BNTiyan)
