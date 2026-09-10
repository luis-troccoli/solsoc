from __future__ import annotations

from rich import box
from rich.console import Console
from rich.table import Table
from rich.text import Text

from solsoc.triage.models import TriageReport, TriageResult

console = Console()

_VERDICT_STYLE = {
    "TRUE_POSITIVE": "bold red",
    "FALSE_POSITIVE": "bold green",
    "NEEDS_REVIEW": "bold yellow",
}

_SEV_STYLE = {
    "CRITICAL": "bold red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "cyan",
    "INFORMATIONAL": "dim",
}


def _confidence_style(score: int) -> str:
    if score >= 80:
        return "bold green"
    elif score >= 50:
        return "yellow"
    else:
        return "bold red"


def print_report(report: TriageReport) -> None:
    """Print a full triage report to the terminal using Rich."""
    console.print()
    console.rule("[bold blue]SolSOC — Alert Triage Report[/bold blue]")
    console.print(
        f"  Provider: [bold]{report.provider}[/bold]  |  "
        f"Total: [bold]{report.total}[/bold]  |  "
        f"[red]TP: {report.true_positives}[/red]  |  "
        f"[green]FP: {report.false_positives}[/green]  |  "
        f"[yellow]Review: {report.needs_review}[/yellow]"
    )
    console.print()

    table = Table(
        box=box.ROUNDED,
        show_header=True,
        header_style="bold blue",
        expand=True,
    )
    table.add_column("ID", style="dim", min_width=14, no_wrap=True)
    table.add_column("Alert", min_width=16, ratio=2)
    table.add_column("Verdict", justify="center", min_width=14, no_wrap=True)
    table.add_column("Severity", justify="center", min_width=12, no_wrap=True)
    table.add_column("Confidence", justify="center", min_width=10, no_wrap=True)
    table.add_column("MITRE", style="dim", min_width=16, ratio=2)
    table.add_column("Reason", min_width=20, ratio=3)
    table.add_column("Action", min_width=20, ratio=3)

    for r in report.results:
        _add_row(table, r)

    console.print(table)

    if any(r.error for r in report.results):
        console.print()
        console.print("[bold yellow]⚠ Errors encountered:[/bold yellow]")
        for r in report.results:
            if r.error:
                console.print(f"  [dim]{r.alert_id}[/dim]: {r.error}")
    console.print()


def _add_row(table: Table, r: TriageResult) -> None:
    verdict_text = Text(r.verdict, style=_VERDICT_STYLE.get(r.verdict, ""))
    severity_text = Text(r.severity, style=_SEV_STYLE.get(r.severity, ""))
    confidence_text = Text(f"{r.confidence_score}%", style=_confidence_style(r.confidence_score))

    table.add_row(
        r.alert_id[:14] + ".." if len(r.alert_id) > 14 else r.alert_id,
        r.alert_title,
        verdict_text,
        severity_text,
        confidence_text,
        r.mitre_technique or "—",
        r.reason,
        r.recommended_action,
    )
