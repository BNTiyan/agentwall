"""Persistent audit ledger for recording agent security events."""

from __future__ import annotations

import json
import os
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional
from agentwall.models import AuditRecord, RiskLevel, SecurityViolation


class AuditLedger:
    """Manages persistent JSONL records of all inspected agent operations."""

    def __init__(self, log_dir: Optional[str] = None):
        if log_dir:
            self.base_dir = Path(log_dir)
        else:
            self.base_dir = Path(os.path.expanduser("~/.agentwall"))
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self.log_file = self.base_dir / "audit.jsonl"

    def record(
        self,
        record: AuditRecord,
        blocked: bool,
        overridden: bool = False,
    ) -> None:
        """Appends an evaluation event to the audit ledger."""
        data = {
            "timestamp": record.timestamp.isoformat(),
            "command": record.command,
            "risk_level": record.risk_level.value,
            "blocked": blocked,
            "overridden": overridden,
            "executed": record.executed,
            "exit_code": record.exit_code,
            "violations": [asdict(v) for v in record.violations],
        }
        with open(self.log_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(data) + "\n")

    def get_recent(self, limit: int = 20) -> List[Dict]:
        """Returns the most recent N audit records."""
        if not self.log_file.exists():
            return []

        records = []
        with open(self.log_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        records.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        return records[-limit:]

    def get_summary(self) -> Dict:
        """Computes aggregate security statistics from the audit ledger."""
        if not self.log_file.exists():
            return {
                "total_inspected": 0,
                "total_blocked": 0,
                "total_overridden": 0,
                "critical_violations": 0,
                "high_violations": 0,
            }

        total_inspected = 0
        total_blocked = 0
        total_overridden = 0
        critical_count = 0
        high_count = 0

        with open(self.log_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    item = json.loads(line)
                    total_inspected += 1
                    if item.get("blocked"):
                        total_blocked += 1
                    if item.get("overridden"):
                        total_overridden += 1
                    risk = item.get("risk_level")
                    if risk == RiskLevel.CRITICAL.value:
                        critical_count += 1
                    elif risk == RiskLevel.HIGH.value:
                        high_count += 1
                except json.JSONDecodeError:
                    continue

        return {
            "total_inspected": total_inspected,
            "total_blocked": total_blocked,
            "total_overridden": total_overridden,
            "critical_violations": critical_count,
            "high_violations": high_count,
        }

    def clear(self) -> None:
        """Clears the audit ledger."""
        if self.log_file.exists():
            self.log_file.unlink()
