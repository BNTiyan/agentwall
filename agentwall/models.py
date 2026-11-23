"""Data structures and risk categorization models for agentwall."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import List, Optional


class RiskLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    SAFE = "SAFE"


@dataclass
class SecurityViolation:
    rule_name: str
    risk_level: RiskLevel
    matched_pattern: str
    description: str
    remediation: str


@dataclass
class AuditRecord:
    command: str
    risk_level: RiskLevel
    violations: List[SecurityViolation] = field(default_factory=list)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    executed: bool = False
    exit_code: Optional[int] = None
