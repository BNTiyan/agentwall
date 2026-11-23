#!/usr/bin/env bash
# Standalone one-line installer for agentwall
set -e

echo "🛡️ Installing agentwall (AI Coding Agent Security Firewall)..."

if command -v uv >/dev/null 2>&1; then
    uv tool install --force git+https://github.com/BNTiyan/agentwall.git
elif command -v pipx >/dev/null 2>&1; then
    pipx install --force git+https://github.com/BNTiyan/agentwall.git
elif command -v pip3 >/dev/null 2>&1; then
    pip3 install --user git+https://github.com/BNTiyan/agentwall.git
else
    echo "❌ Error: Python 3 and pip or uv are required to install agentwall."
    exit 1
fi

echo "✅ agentwall successfully installed!"
echo "Run 'agentwall demo' to explore the command interception gate."
echo "Run 'agentwall check \"rm -rf /\"' to evaluate any command."
