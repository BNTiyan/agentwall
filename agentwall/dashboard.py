"""Rich Terminal UI Dashboard for agentwall security events."""

from __future__ import annotations

from typing import List
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.layout import Layout

from agentwall.models import AuditRecord, RiskLevel

console = Console()


def render_banner() -> Panel:
    title = Text("🛡️ AGENTWALL — Autonomous Agent Security Shield", style="bold red")
    content = Text()
    content.append("Zero-Config Command Guard, Path Sandbox & Secret Leak Interceptor\n", style="bold white")
    content.append("Protecting host systems from rogue coding agents ● Real-Time Blast Radius Control", style="dim cyan")
    return Panel(content, title=title, border_style="red", padding=(0, 1))


def render_violation_card(record: AuditRecord) -> Panel:
    risk_color = (
        "bold red" if record.risk_level == RiskLevel.CRITICAL
        else "bold yellow" if record.risk_level == RiskLevel.HIGH
        else "bold green"
    )

    table = Table(show_header=False, expand=True, box=None)
    table.add_column("Field", style="bold white", width=18)
    table.add_column("Details", style="cyan")

    table.add_row("Evaluated Command", f"[bold white]{record.command}[/bold white]")
    table.add_row("Risk Assessment", f"[{risk_color}]{record.risk_level.value}[/{risk_color}]")
    table.add_row("Execution Verdict", "[bold red]🛑 INTERCEPTED & BLOCKED[/bold red]" if record.violations else "[bold green]✓ PERMITTED[/bold green]")

    v_table = Table(
        title="⚠️ Detected Security Violations",
        header_style="bold red",
        border_style="red",
        expand=True,
    )
    v_table.add_column("Rule Name", style="bold red", width=22)
    v_table.add_column("Trigger Pattern", style="yellow", width=20)
    v_table.add_column("Description & Remediation", style="dim white")

    for v in record.violations:
        v_table.add_row(v.rule_name, v.matched_pattern, f"{v.description}\n[green]→ {v.remediation}[/green]")

    layout = Layout()
    layout.split_column(
        Layout(Panel(table, title="[bold]Command Audit[/bold]", border_style="blue")),
        Layout(v_table),
    )

    border_color = "red" if record.risk_level in (RiskLevel.CRITICAL, RiskLevel.HIGH) else "green"
    return Panel(layout, title="🛡️ Security Gate Evaluation", border_style=border_color, padding=(1, 2))
