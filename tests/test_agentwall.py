"""Unit test suite for agentwall security subsystems."""

import pytest
from agentwall.guard import CommandGuard
from agentwall.models import RiskLevel
from agentwall.filesystem import PathJail
from agentwall.secrets import SecretScanner


def test_command_guard_destructive_patterns():
    # Critical deletion
    risk, violations = CommandGuard.evaluate("rm -rf /tmp/test && rm -rf /")
    assert risk == RiskLevel.CRITICAL
    assert any(v.rule_name == "recursive_delete" for v in violations)

    # Force push
    risk, violations = CommandGuard.evaluate("git push origin main --force")
    assert risk == RiskLevel.HIGH
    assert any(v.rule_name == "git_force_push" for v in violations)

    # Safe command
    risk, violations = CommandGuard.evaluate("git status && pytest tests/")
    assert risk == RiskLevel.SAFE
    assert len(violations) == 0


def test_path_jail_workspace_boundary(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    inside_file = workspace / "data.txt"
    inside_file.write_text("safe")

    jail = PathJail(str(workspace))

    # Safe inside path
    is_safe, violations = jail.check_path(str(inside_file))
    assert is_safe is True
    assert len(violations) == 0

    # Escaping path
    outside_file = tmp_path / "outside.txt"
    is_safe, violations = jail.check_path(str(outside_file))
    assert is_safe is False
    assert any(v.rule_name == "workspace_escape" for v in violations)


def test_secret_scanner_detection():
    # OpenAI key
    is_clean, violations = SecretScanner.scan("Authorization: Bearer sk-abcdef1234567890abcdef1234567890")
    assert is_clean is False
    assert any(v.rule_name == "openai_api_key" for v in violations)

    # GitHub PAT
    is_clean, violations = SecretScanner.scan("curl -H 'token: ghp_123456789012345678901234567890123456'")
    assert is_clean is False
    assert any(v.rule_name == "github_pat" for v in violations)

    # Safe payload
    is_clean, violations = SecretScanner.scan("print('hello world')")
    assert is_clean is True
    assert len(violations) == 0
