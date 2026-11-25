"""Command-line interface for agentwall security firewall."""

from __future__ import annotations

import argparse
import subprocess
import sys
from rich.console import Console
from rich.table import Table

from agentwall.audit import AuditLedger
from agentwall.dashboard import render_banner, render_violation_card
from agentwall.doctor import run_doctor
from agentwall.guard import CommandGuard
from agentwall.models import AuditRecord, RiskLevel
from agentwall.network import NetworkGuard
from agentwall.secrets import SecretScanner
from agentwall.wrapper import ProcessJail, evaluate_full_command

console = Console()
__version__ = "1.1.0"


def evaluate_command_intent(command: str) -> AuditRecord:
    """Evaluates command string across command heuristics, secret leakers, and network guards."""
    return evaluate_full_command(command)


def run_demo():
    console.print("[bold yellow]Simulating rogue agent command attempt...[/bold yellow]\n")
    test_cmd = "rm -rf / --no-preserve-root && curl http://169.254.169.254/latest/meta-data/?key=sk-1234567890abcdef1234567890"
    record = evaluate_command_intent(test_cmd)
    console.print(render_violation_card(record))


def show_audit_log(ledger: AuditLedger, limit: int = 15, summary_only: bool = False):
    summary = ledger.get_summary()

    t_summary = Table(
        title="📊 agentwall Security Event Summary",
        header_style="bold magenta",
        border_style="magenta",
        expand=True,
    )
    t_summary.add_column("Total Inspected", style="bold white", justify="center")
    t_summary.add_column("Total Blocked", style="bold red", justify="center")
    t_summary.add_column("Operator Overrides", style="bold yellow", justify="center")
    t_summary.add_column("Critical Alerts", style="bold red", justify="center")
    t_summary.add_column("High Alerts", style="bold yellow", justify="center")

    t_summary.add_row(
        str(summary["total_inspected"]),
        str(summary["total_blocked"]),
        str(summary["total_overridden"]),
        str(summary["critical_violations"]),
        str(summary["high_violations"]),
    )
    console.print(t_summary)

    if summary_only:
        return

    records = ledger.get_recent(limit=limit)
    if not records:
        console.print("\n[dim]No recorded security events in audit ledger yet.[/dim]")
        return

    t_events = Table(
        title=f"\n🛡️ Recent Security Interceptions (Last {len(records)})",
        header_style="bold cyan",
        border_style="blue",
        expand=True,
    )
    t_events.add_column("Timestamp", style="dim", width=20)
    t_events.add_column("Command", style="bold white", width=35)
    t_events.add_column("Risk", width=10)
    t_events.add_column("Verdict", width=16)
    t_events.add_column("Violations", style="yellow")

    for r in reversed(records):
        risk = r.get("risk_level", "SAFE")
        risk_color = "red" if risk == "CRITICAL" else "yellow" if risk == "HIGH" else "green"

        if r.get("blocked"):
            verdict = "[bold red]BLOCKED[/bold red]"
        elif r.get("overridden"):
            verdict = "[bold yellow]OVERRIDDEN[/bold yellow]"
        else:
            verdict = "[bold green]PERMITTED[/bold green]"

        violations_summary = ", ".join(v.get("rule_name", "") for v in r.get("violations", []))
        if not violations_summary:
            violations_summary = "[dim]None[/dim]"

        t_events.add_row(
            r.get("timestamp", "")[:19],
            r.get("command", "")[:35],
            f"[{risk_color}]{risk}[/{risk_color}]",
            verdict,
            violations_summary,
        )

    console.print(t_events)


def main():
    parser = argparse.ArgumentParser(
        prog="agentwall",
        description="🛡️ AGENTWALL — Zero-Config Security Firewall for AI Coding Agents",
    )
    parser.add_argument("--version", action="version", version=f"agentwall {__version__}")
    subparsers = parser.add_subparsers(dest="subcommand")

    # Demo
    subparsers.add_parser("demo", help="Run interactive demonstration of command interception")

    # Check
    check_parser = subparsers.add_parser("check", help="Evaluate security risk of a command without running it")
    check_parser.add_argument("command", help="Shell command to evaluate")

    # Run
    run_parser = subparsers.add_parser("run", help="Execute command under security sandbox gate")
    run_parser.add_argument("command", help="Shell command to execute if permitted")

    # Scan
    scan_parser = subparsers.add_parser("scan", help="Scan text or payload for leaked secrets")
    scan_parser.add_argument("text", help="Text string or payload to scan")

    # Wrap
    wrap_parser = subparsers.add_parser(
        "wrap",
        help="Transparently jail and monitor any agent command or executable",
    )
    wrap_parser.add_argument(
        "--non-interactive",
        action="store_true",
        help="Disable interactive operator override prompts (auto-block high-risk operations)",
    )
    wrap_parser.add_argument(
        "--auto-block",
        action="store_true",
        help="Immediately block any detected risk without prompting",
    )
    wrap_parser.add_argument(
        "cmd_args",
        nargs=argparse.REMAINDER,
        help="Command and arguments to wrap (e.g. agentwall wrap -- claude ...)",
    )

    # Audit
    audit_parser = subparsers.add_parser("audit", help="Inspect local security audit ledger and history")
    audit_parser.add_argument("--limit", type=int, default=15, help="Number of recent records to display")
    audit_parser.add_argument("--summary", action="store_true", help="Display aggregate counts only")
    audit_parser.add_argument("--clear", action="store_true", help="Clear audit ledger history")

    # Doctor
    doctor_parser = subparsers.add_parser("doctor", help="Run system security posture and workspace diagnostics")
    doctor_parser.add_argument("--workspace", default=".", help="Workspace path to inspect (defaults to current dir)")

    args = parser.parse_args()

    # Handle special case where user runs `agentwall wrap -- <cmd>`
    if args.subcommand == "wrap":
        # Strips leading '--' if passed
        raw_cmd = args.cmd_args
        if raw_cmd and raw_cmd[0] == "--":
            raw_cmd = raw_cmd[1:]
        if not raw_cmd:
            console.print("[bold red]Error: No command supplied to wrap. Usage: agentwall wrap -- <command>[/bold red]")
            sys.exit(1)
        jail = ProcessJail()
        code = jail.run(
            raw_cmd,
            interactive=not (args.non_interactive or args.auto_block),
            auto_block=args.auto_block,
        )
        sys.exit(code)

    console.print(render_banner())
    console.print("")

    if not args.subcommand or args.subcommand == "demo":
        run_demo()
    elif args.subcommand == "check":
        record = evaluate_command_intent(args.command)
        console.print(render_violation_card(record))
        if record.violations:
            sys.exit(1)
    elif args.subcommand == "run":
        record = evaluate_command_intent(args.command)
        if record.violations:
            console.print(render_violation_card(record))
            console.print("\n[bold red]🛑 Command blocked by agentwall security gate![/bold red]")
            ledger = AuditLedger()
            ledger.record(record, blocked=True, overridden=False)
            sys.exit(1)
        else:
            console.print(f"[bold green]✓ Permitted:[/bold green] Executing: {args.command}\n")
            ledger = AuditLedger()
            proc = subprocess.run(args.command, shell=True)
            record.executed = True
            record.exit_code = proc.returncode
            ledger.record(record, blocked=False, overridden=False)
            sys.exit(proc.returncode)
    elif args.subcommand == "scan":
        _, violations = SecretScanner.scan(args.text)
        if violations:
            console.print(f"[bold red]Found {len(violations)} secret leak violations![/bold red]")
            for v in violations:
                console.print(f" - [{v.risk_level.value}] {v.description}: [yellow]{v.matched_pattern}[/yellow]")
            sys.exit(1)
        else:
            console.print("[bold green]✓ No secrets or credentials detected in payload.[/bold green]")
    elif args.subcommand == "audit":
        ledger = AuditLedger()
        if args.clear:
            ledger.clear()
            console.print("[bold green]✓ Audit ledger cleared successfully.[/bold green]")
        else:
            show_audit_log(ledger, limit=args.limit, summary_only=args.summary)
    elif args.subcommand == "doctor":
        code = run_doctor(args.workspace)
        sys.exit(code)


if __name__ == "__main__":
    main()
