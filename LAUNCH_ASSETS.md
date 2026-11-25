# agentwall v1.1.0 Viral Launch Assets

Targeting viral organic traction across developer communities (Show HN, Reddit, X/Twitter).

---

## 1. Show HN (Hacker News)

**Title**: Show HN: Agentwall – Zero-config security firewall for Claude Code, Cursor, and Cline

**Link**: `https://github.com/BNTiyan/agentwall`

**Text Body**:
```text
Hey HN,

Over the past few months, I’ve been running autonomous coding agents like Claude Code, Cursor, and Cline for local development.

While they are incredible productivity multipliers, giving an LLM raw subshell execution on your developer machine is terrifying:
1. Hallucinated destructive commands: `rm -rf /` or `git push --force` to main.
2. Cloud Metadata SSRF: If an agent runs in a cloud VM or Codespace, prompt injections can query `169.254.169.254` to steal IAM instance credentials.
3. Path escapes: Agents traversing out of workspace to read `~/.ssh` or `~/.aws`.
4. Credential leaks: Accidentally echoing API keys or secrets into remote logs.

Running everything inside heavy Docker containers or VMs solves isolation, but introduces 5-10s startup delays and breaks local development ergonomics (host SSH keys, local toolchains, dev servers).

I built **agentwall** (MIT, zero cloud dependencies, <5ms startup):
https://github.com/BNTiyan/agentwall

Key features:
- `agentwall wrap -- <command>`: Transparent process wrapper that intercepts high-risk commands and renders a Rich Bento confirmation modal for human-in-the-loop authorization, or auto-blocks in CI (`--auto-block`).
- SSRF & Reverse Shell Guard: Heuristics intercepting AWS/GCP metadata queries, netcat reverse shells, and `/dev/tcp` pipes.
- Workspace Path Jail: Locks filesystem access to the current workspace root; blocks access to `~/.ssh`, `~/.aws`, `/etc`.
- Secret Scanner: Catches API keys (`sk-...`, `ghp_...`, AWS keys) before network transmission.
- Audit Ledger & Doctor: Local immutable JSONL audit history (`agentwall audit`) and security posture diagnostics (`agentwall doctor`).

It installs in one line:
curl -fsSL https://raw.githubusercontent.com/BNTiyan/agentwall/main/install.sh | bash

Would love feedback on additional heuristic rules or integrations you’d like to see!
```

---

## 2. Reddit (`r/LocalLLaMA`, `r/cybersecurity`, `r/programming`)

**Title**: I built a zero-overhead security firewall for AI coding agents (Claude Code, Cursor, Cline) to stop `rm -rf`, metadata SSRF, and credential leaks

**Post**:
```text
Hey everyone,

With autonomous coding agents gaining widespread adoption, we are routinely letting LLMs execute raw shell commands on our personal dev setups.

The problem: Docker VMs are slow and break host ergonomics, while running bare-metal risks catastrophic hallucinations or indirect prompt injections (e.g. malicious dependencies or README files instructing the agent to exfiltrate ~/.ssh or run destructive commands).

I built **agentwall**: a zero-config, <5ms security shield that wraps your agent commands:
👉 GitHub: https://github.com/BNTiyan/agentwall

What it does:
🛡️ Intercepts Destructive Commands: `rm -rf /`, `dd if=/dev/`, `chmod 777`, `git push --force`, `DROP TABLE`.
🛡️ Intercepts Cloud SSRF: Catches attempts to hit 169.254.169.254 or metadata.google.internal to steal cloud IAM tokens.
🛡️ Path Jail: Strictly bars agents from reading or modifying ~/.ssh, ~/.aws, ~/.gnupg, or /etc.
🛡️ Secret Leaker Protection: Regex scanner for OpenAI, GitHub, and AWS keys before they leave your machine.
🛡️ Transparent Wrapper: `agentwall wrap -- <your-agent>` with interactive human-in-the-loop approval or auto-block in headless CI.
🛡️ Local Audit Ledger: Immutable audit history via `agentwall audit`.

Install with:
pip install agentwall
# or
curl -fsSL https://raw.githubusercontent.com/BNTiyan/agentwall/main/install.sh | bash

Check it out and let me know what rules we should add to the default heuristics!
```

---

## 3. X / Twitter Launch Thread

**Post 1 (Hook)**:
```text
Giving autonomous AI coding agents raw shell access on your machine is a disaster waiting to happen.

One hallucination or prompt injection = `rm -rf /`, force-pushing over main, or exfiltrating your cloud credentials.

Introducing agentwall 🛡️: A zero-config security firewall for Claude Code, Cursor, and Cline.

👇 (1/5)
```

**Post 2 (Features)**:
```text
Unlike heavy Docker containers that take 5-10s to boot and break host tooling, agentwall has <5ms overhead.

It intercepts:
• `rm -rf /`, `dd`, `DROP TABLE`, `git push --force`
• AWS/GCP Metadata SSRF (169.254.169.254)
• Workspace path escapes (~/.ssh, ~/.aws)
• Leaked API keys & PATs

(2/5)
```

**Post 3 (Wrap & Human-in-the-Loop)**:
```text
With v1.1.0, you can now wrap any agent transparently:

agentwall wrap -- claude

If a high-risk operation is detected, agentwall renders a clean terminal Bento modal asking for human confirmation. In CI, pass `--auto-block` for automated protection.

(3/5)
```

**Post 4 (Audit & Doctor)**:
```text
Also shipped in v1.1.0:
• `agentwall audit`: Local immutable JSONL security ledger of every intercepted command.
• `agentwall doctor`: Workspace security posture health check.

100% open-source under MIT, zero cloud cost, zero telemetry.

(4/5)
```

**Post 5 (CTA)**:
```text
Star & install agentwall on GitHub:
⭐ https://github.com/BNTiyan/agentwall

Install via curl:
curl -fsSL https://raw.githubusercontent.com/BNTiyan/agentwall/main/install.sh | bash

Let me know what you think! 🚀 (5/5)
```
