"""Destructive command pattern detection and execution barrier."""

from __future__ import annotations

import re
from typing import List, Tuple
from agentwall.models import RiskLevel, SecurityViolation

DESTRUCTIVE_RULES = [
    {
        "name": "recursive_delete",
        "pattern": r"(?:\brm\b\s+-[^\s]*r[^\s]*f?\s+[\/~]|\brm\b\s+-[^\s]*f[^\s]*r?\s+[\/~])",
        "risk": RiskLevel.CRITICAL,
        "description": "Attempt to delete root or home filesystem recursively (rm -rf / or ~)",
        "remediation": "Restrict deletions to specific workspace files or use a trash manager."
    },
    {
        "name": "raw_disk_write",
        "pattern": r"\bdd\b\s+if=.*?of=\/dev\/",
        "risk": RiskLevel.CRITICAL,
        "description": "Direct raw block device write (potential partition wipe)",
        "remediation": "Direct writes to /dev block devices are forbidden."
    },
    {
        "name": "git_force_push",
        "pattern": r"\bgit\b\s+push\b.*?(?:--force\b|-f\b)",
        "risk": RiskLevel.HIGH,
        "description": "Forced remote push can overwrite shared branch history and cause data loss",
        "remediation": "Use standard non-force git push or push to an isolated feature branch."
    },
    {
        "name": "unverified_remote_exec",
        "pattern": r"(?:curl|wget)\s+.*?\s*\|\s*(?:bash|sh|zsh|sudo)",
        "risk": RiskLevel.HIGH,
        "description": "Piping unverified remote web script directly into a shell interpreter",
        "remediation": "Download the script first, inspect its contents, and run with explicit review."
    },
    {
        "name": "wildcard_permission_escalation",
        "pattern": r"\bchmod\b\s+(?:-R\s+)?777\b",
        "risk": RiskLevel.HIGH,
        "description": "Overly permissive world-writable file permission escalation (chmod 777)",
        "remediation": "Use least-privilege permissions (e.g., 644 or 755)."
    },
    {
        "name": "database_destructive_query",
        "pattern": r"(?i)\b(?:drop\s+(?:database|table)|truncate\s+table)\b",
        "risk": RiskLevel.CRITICAL,
        "description": "Irreversible SQL destruction command (DROP/TRUNCATE)",
        "remediation": "Database schema drops must be run manually through migrations."
    }
]


class CommandGuard:
    """Evaluates raw shell commands against security heuristics and risk profiles."""

    @classmethod
    def evaluate(cls, command: str) -> Tuple[RiskLevel, List[SecurityViolation]]:
        violations: List[SecurityViolation] = []
        highest_risk = RiskLevel.SAFE

        for rule in DESTRUCTIVE_RULES:
            match = re.search(rule["pattern"], command)
            if match:
                violation = SecurityViolation(
                    rule_name=rule["name"],
                    risk_level=rule["risk"],
                    matched_pattern=match.group(0),
                    description=rule["description"],
                    remediation=rule["remediation"],
                )
                violations.append(violation)

                if rule["risk"] == RiskLevel.CRITICAL:
                    highest_risk = RiskLevel.CRITICAL
                elif rule["risk"] == RiskLevel.HIGH and highest_risk != RiskLevel.CRITICAL:
                    highest_risk = RiskLevel.HIGH
                elif rule["risk"] == RiskLevel.MEDIUM and highest_risk == RiskLevel.SAFE:
                    highest_risk = RiskLevel.MEDIUM

        return highest_risk, violations
