"""Filesystem boundary enforcement and path jail."""

from __future__ import annotations

import os
from typing import List, Tuple
from agentwall.models import RiskLevel, SecurityViolation

SENSITIVE_TARGETS = [
    os.path.expanduser("~/.ssh"),
    os.path.expanduser("~/.aws"),
    os.path.expanduser("~/.gnupg"),
    os.path.expanduser("~/.bashrc"),
    os.path.expanduser("~/.zshrc"),
    "/etc",
    "/var/root",
]


class PathJail:
    """Ensures agent file paths stay strictly bounded inside an allowed workspace root."""

    def __init__(self, workspace_root: str):
        self.workspace_root = os.path.realpath(os.path.abspath(workspace_root))

    def check_path(self, target_path: str) -> Tuple[bool, List[SecurityViolation]]:
        violations: List[SecurityViolation] = []
        resolved = os.path.realpath(os.path.abspath(target_path))

        # Check if targeting sensitive host files
        for sensitive in SENSITIVE_TARGETS:
            if resolved == sensitive or resolved.startswith(sensitive + os.sep):
                violations.append(
                    SecurityViolation(
                        rule_name="sensitive_host_access",
                        risk_level=RiskLevel.CRITICAL,
                        matched_pattern=target_path,
                        description=f"Attempted access to protected host location '{sensitive}'",
                        remediation="Agents are strictly barred from reading or modifying host credentials.",
                    )
                )

        # Check if path escapes workspace root
        if not (resolved == self.workspace_root or resolved.startswith(self.workspace_root + os.sep)):
            violations.append(
                SecurityViolation(
                    rule_name="workspace_escape",
                    risk_level=RiskLevel.HIGH,
                    matched_pattern=target_path,
                    description=f"Path '{target_path}' escapes workspace boundary '{self.workspace_root}'",
                    remediation="All agent operations must remain inside the designated workspace.",
                )
            )

        return len(violations) == 0, violations
