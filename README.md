<div align="center">

# agentwall 🛡️

**Zero-Config Security Firewall & Blast-Radius Shield for AI Coding Agents**

[![CI](https://github.com/BNTiyan/agentwall/actions/workflows/ci.yml/badge.svg)](https://github.com/BNTiyan/agentwall/actions)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Zero-Cloud-Cost](https://img.shields.io/badge/cost-$0.00-brightgreen.svg)](#)

*Intercept rogue commands, prevent filesystem escapes, and stop credential leaks from Claude Code, Cursor, and Cline.*

<br/>

<img src="assets/demo.svg" alt="agentwall Terminal Interception" width="100%"/>

</div>

---

## Why agentwall?

Autonomous coding agents (Claude Code, Cursor, Cline, OpenCode) execute shell commands directly on your development machine. Without guardrails, an LLM hallucination or malicious prompt injection can execute `rm -rf`, force-push breaking changes to main, overwrite `/etc` or `~/.bashrc`, or leak `.env` API keys across unauthorized network pipes.

`agentwall` is an instantaneous, zero-overhead security wrapper that intercepts and blocks dangerous operations before they touch your operating system.

| Security Capability | `agentwall` | Raw Terminal Execution | Heavy Docker VM |
| :--- | :--- | :--- | :--- |
| **Startup Overhead** | **< 5ms (Instant)** | 0ms | 3-10 seconds |
| **Destructive Command Interception** | **Yes (`rm -rf`, `dd`, `drop table`)** | No (Executes immediately) | Partial |
| **Filesystem Jail** | **Workspace Locked (`~/.ssh` protected)** | Unrestricted | Locked |
| **Secret Leak Scanner** | **Automated (API keys, PATs, SSH keys)**| None | None |
| **Interactive Terminal TUI** | **Rich Real-Time Security Scorecard** | None | None |
| **Host System Convenience** | **Full Host Tooling (git, uv, npm)** | Full | Isolated (Requires rebuilds) |

---

## Highlights

- **Destructive Command Guard**: Intercepts `rm -rf /`, `dd if=/dev`, `chmod 777`, `git push --force`, and `DROP TABLE` before execution.
- **Path Jail Boundary**: Locks agent filesystem access strictly to the current workspace root; blocks access to `~/.ssh`, `~/.aws`, `~/.config`, and `/etc`.
- **Secret Leaker Guard**: Scans command strings and output payloads for accidental leaks of OpenAI keys (`sk-...`), GitHub PATs (`ghp_...`), AWS keys, and private SSH keys.
- **Rich Terminal Security Card**: Displays real-time risk assessment (`CRITICAL`, `HIGH`, `SAFE`), matched patterns, and remediation steps.

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

### 1. Try the Built-in Security Demo
```bash
agentwall demo
```

### 2. Pre-Check Any Command (Dry-Run)
Check a command's risk level without executing it:
```bash
agentwall check "rm -rf / --no-preserve-root"
```

### 3. Wrap Any Agent Execution
Wrap any agent or script with the security firewall:
```bash
agentwall run "python my_agent.py"
```

### 4. Scan Payloads for Leaked Credentials
```bash
agentwall scan "export OPENAI_API_KEY=sk-proj-1234567890abcdef1234567890"
```

---

## Running the Test Suite

```bash
pytest tests/ -v
```

All security subsystems (command interception, path jail, secret scanning) are tested with 100% pass verification.

---

## Contributing

Security researchers and developers are welcome to propose additional heuristic rules and detection patterns via Pull Requests!

---

## License

MIT © [BNTiyan](https://github.com/BNTiyan)
