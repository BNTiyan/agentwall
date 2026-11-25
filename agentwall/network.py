"""Network egress and SSRF attack detection."""

from __future__ import annotations

import re
from typing import List, Tuple
from agentwall.models import RiskLevel, SecurityViolation

NETWORK_RULES = [
    {
        "name": "cloud_metadata_ssrf",
        "pattern": r"(?:169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200)",
        "risk": RiskLevel.CRITICAL,
        "description": "Attempt to query cloud instance metadata service (SSRF / IAM credential theft)",
        "remediation": "Do not query instance metadata endpoints from agent execution environments.",
    },
    {
        "name": "reverse_shell_netcat",
        "pattern": r"\b(?:nc|ncat|netcat)\b.*?\s+-[a-zA-Z]*e\s+(?:\/bin\/(?:ba)?sh|cmd\.exe)",
        "risk": RiskLevel.CRITICAL,
        "description": "Reverse shell execution via netcat (-e /bin/sh)",
        "remediation": "Reverse shell payloads are prohibited.",
    },
    {
        "name": "reverse_shell_dev_tcp",
        "pattern": r"\/dev\/tcp\/[0-9a-zA-Z\.\-]+\/[0-9]+",
        "risk": RiskLevel.CRITICAL,
        "description": "Direct bash /dev/tcp outbound socket invocation (reverse shell)",
        "remediation": "Raw /dev/tcp socket redirection is barred.",
    },
    {
        "name": "reverse_shell_python_socket",
        "pattern": r"python(?:3)?\s+-c\s+['\"].*?import\s+socket.*?connect\(.*?['\"]",
        "risk": RiskLevel.CRITICAL,
        "description": "Inline Python socket connection payload (reverse shell pattern)",
        "remediation": "Direct socket spawning from one-line scripts is blocked.",
    },
    {
        "name": "unauthorized_data_pipe",
        "pattern": r"tar\s+-[^\s]*c[^\s]*\s+.*?\s*\|\s*(?:curl|wget|nc)\b",
        "risk": RiskLevel.HIGH,
        "description": "Archiving files and streaming directly across a network pipe (exfiltration)",
        "remediation": "Explicitly save archives locally and verify contents before transmission.",
    },
]


class NetworkGuard:
    """Detects suspicious outbound network connections, reverse shells, and SSRF attacks."""

    @classmethod
    def evaluate(cls, command: str) -> Tuple[RiskLevel, List[SecurityViolation]]:
        violations: List[SecurityViolation] = []
        highest_risk = RiskLevel.SAFE

        for rule in NETWORK_RULES:
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
