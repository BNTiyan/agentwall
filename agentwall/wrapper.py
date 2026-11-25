"""Process wrapper and transparent execution jail for AI coding agents."""

from __future__ import annotations

import shlex
import subprocess
import sys
from typing import List, Optional
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm

from agentwall.dashboard import render_violation_card
from agentwall.guard import CommandGuard
from agentwall.models import AuditRecord, RiskLevel, SecurityViolation
from agentwall.network import NetworkGuard
from agentwall.secrets import SecretScanner
from agentwall.audit import AuditLedger

console = Console()


def evaluate_full_command(command: str) -> AuditRecord:
    """Aggregates security evaluation across all detection engines."""
    risk_cmd, violations_cmd = CommandGuard.evaluate(command)
    _, violations_sec = SecretScanner.scan(command)
    risk_net, violations_net = NetworkGuard.evaluate(command)

    all_violations = violations_cmd + violations_sec + violations_net

    # Calculate composite highest risk
    if any(v.risk_level == RiskLevel.CRITICAL for v in all_violations):
        highest_risk = RiskLevel.CRITICAL
    elif any(v.risk_level == RiskLevel.HIGH for v in all_violations):
        highest_risk = RiskLevel.HIGH
    elif any(v.risk_level == RiskLevel.MEDIUM for v in all_violations):
        highest_risk = RiskLevel.MEDIUM
    else:
        highest_risk = RiskLevel.SAFE

    return AuditRecord(
        command=command,
        risk_level=highest_risk,
        violations=all_violations,
    )


class ProcessJail:
    """Executes child commands under an active interception and approval barrier."""

    def __init__(self, ledger: Optional[AuditLedger] = None):
        self.ledger = ledger or AuditLedger()

    def run(
        self,
        command_args: List[str],
        interactive: bool = True,
        auto_block: bool = False,
    ) -> int:
        """Evaluates command_args and either blocks, prompts for approval, or executes."""
        if not command_args:
            console.print("[red]Error: No command specified to wrap.[/red]")
            return 1

        command_str = " ".join(command_args)
        record = evaluate_full_command(command_str)

        if not record.violations:
            # Clean command - execute directly
            record.executed = True
            proc = subprocess.run(command_args)
            record.exit_code = proc.returncode
            self.ledger.record(record, blocked=False, overridden=False)
            return proc.returncode

        # Violations detected
        console.print(render_violation_card(record))

        if auto_block or not interactive:
            console.print("\n[bold red]🛑 Command BLOCKED by agentwall security gate![/bold red]")
            record.executed = False
            record.exit_code = 126
            self.ledger.record(record, blocked=True, overridden=False)
            return 126

        # Interactive human-in-the-loop authorization prompt
        console.print("\n[bold yellow]⚠️  Security threshold exceeded for this operation.[/bold yellow]")
        try:
            approved = Confirm.ask(
                "[bold cyan]Do you wish to authorize and execute this command anyway?[/bold cyan]",
                default=False,
            )
        except (KeyboardInterrupt, EOFError):
            approved = False

        if approved:
            console.print(f"[bold yellow]⚠️  Operator Override Granted.[/bold yellow] Executing: {command_str}\n")
            record.executed = True
            proc = subprocess.run(command_args)
            record.exit_code = proc.returncode
            self.ledger.record(record, blocked=False, overridden=True)
            return proc.returncode
        else:
            console.print("[bold red]🛑 Operation rejected by operator.[/bold red]")
            record.executed = False
            record.exit_code = 126
            self.ledger.record(record, blocked=True, overridden=False)
            return 126
