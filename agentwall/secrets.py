"""Secret leak detector scanning command strings and outputs."""

from __future__ import annotations

import re
from typing import List, Tuple
from agentwall.models import RiskLevel, SecurityViolation

SECRET_PATTERNS = [
    {
        "name": "openai_api_key",
        "pattern": r"\bsk-[a-zA-Z0-9_-]{20,}\b",
        "desc": "OpenAI API secret key leak",
    },
    {
        "name": "github_pat",
        "pattern": r"\bghp_[a-zA-Z0-9]{36}\b",
        "desc": "GitHub Personal Access Token leak",
    },
    {
        "name": "aws_access_key",
        "pattern": r"\bAKIA[0-9A-Z]{16}\b",
        "desc": "AWS Access Key ID leak",
    },
    {
        "name": "private_ssh_key",
        "pattern": r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
        "desc": "Private SSH/Cryptographic key block leak",
    },
]


class SecretScanner:
    """Scans payload text to prevent accidental exfiltration of confidential credentials."""

    @classmethod
    def scan(cls, content: str) -> Tuple[bool, List[SecurityViolation]]:
        violations: List[SecurityViolation] = []
        for rule in SECRET_PATTERNS:
            matches = re.finditer(rule["pattern"], content)
            for m in matches:
                matched_val = m.group(0)
                masked = matched_val[:4] + "..." + matched_val[-4:]
                violations.append(
                    SecurityViolation(
                        rule_name=rule["name"],
                        risk_level=RiskLevel.CRITICAL,
                        matched_pattern=masked,
                        description=rule["desc"],
                        remediation="Ensure credentials are supplied via environment variables, not raw text.",
                    )
                )

        return len(violations) == 0, violations
