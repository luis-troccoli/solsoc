from __future__ import annotations
import sys
from pathlib import Path
from typing import Optional
import typer
from rich.console import Console

app = typer.Typer(
    name="solsoc",
    help="SolSOC — AI-powered SOC alert triage. Cut through the noise, surface what matters.",
    add_completion=False,
)
console = Console(stderr=True)


def _read_input(source: str) -> tuple[str, str | None]:
    """
    Read alert content from a file path or stdin ('-').
    Returns (content, format_hint) where format_hint is the file extension or None.
    """
    if source == "-":
        content = sys.stdin.read()
        return content, None

    path = Path(source)
    if not path.exists():
        console.print(f"[bold red]Error:[/bold red] File not found: {source}")
        raise typer.Exit(code=1)

    content = path.read_text(encoding="utf-8")
    hint = path.suffix.lstrip(".").lower() or None
    return content, hint


def _run_output(report, format: str | None, output: str | None) -> None:
    """Shared output logic for triage and pull commands."""
    from solsoc.output.rich_output import print_report
    from solsoc.output.json_output import print_json

    use_html = (format == "html") or (output is not None and output.endswith(".html"))
    use_json = (format == "json") or (output is not None and not output.endswith(".html"))

    if use_html:
        from solsoc.output.html_output import render_html
        render_html(report, output_path=output)
        if output:
            console.print(f"[dim]HTML report saved to: {output}[/dim]")
        else:
            sys.stdout.write(render_html(report))
    elif use_json:
        print_json(report, output_path=output)
    else:
        print_report(report)


@app.command()
def triage(
    source: str = typer.Argument(
        ...,
        help="Path to alert file (JSON or CSV) or '-' to read from stdin.",
    ),
    provider: str = typer.Option(
        "anthropic",
        "--provider", "-p",
        help="LLM provider to use: anthropic | openai | gemini",
    ),
    format: Optional[str] = typer.Option(
        None,
        "--format", "-f",
        help="Output format: table (default) | json | html",
    ),
    output: Optional[str] = typer.Option(
        None,
        "--output", "-o",
        help="Save output to this file path (.json or .html).",
    ),
    input_format: Optional[str] = typer.Option(
        None,
        "--input-format",
        help="Override auto-detection: json | csv",
    ),
    batch: int = typer.Option(
        10,
        "--batch", "-b",
        help="Number of alerts to process per batch (default: 10).",
        min=1,
    ),
) -> None:
    """
    Triage a file of SIEM alerts using an LLM and report verdicts.

    Examples:\n
      solsoc triage alerts.json\n
      solsoc triage alerts.csv --provider openai\n
      cat alerts.json | solsoc triage - --provider gemini\n
      solsoc triage alerts.json --format html --output report.html
    """
    from solsoc.parsers.auto import detect_and_parse
    from solsoc.config import get_provider
    from solsoc.triage.engine import run_triage

    try:
        content, hint = _read_input(source)
    except typer.Exit:
        raise

    if not content.strip():
        console.print("[bold red]Error:[/bold red] Input is empty.")
        raise typer.Exit(code=1)

    console.print("[dim]Parsing alerts...[/dim]")
    try:
        alerts = detect_and_parse(content, hint=input_format or hint)
    except Exception as exc:
        console.print(f"[bold red]Parse error:[/bold red] {exc}")
        raise typer.Exit(code=1)

    if not alerts:
        console.print("[yellow]No alerts found in input.[/yellow]")
        raise typer.Exit(code=0)

    console.print(f"[dim]Found {len(alerts)} alert(s). Triaging with [bold]{provider}[/bold]...[/dim]")

    try:
        llm = get_provider(provider)
    except ValueError as exc:
        console.print(f"[bold red]Provider error:[/bold red] {exc}")
        raise typer.Exit(code=1)

    report = run_triage(alerts, llm, batch_size=batch)
    _run_output(report, format, output)


@app.command()
def pull(
    siem: str = typer.Argument(
        ...,
        help="SIEM to pull from: wazuh | sentinel | splunk",
    ),
    provider: str = typer.Option(
        "anthropic",
        "--provider", "-p",
        help="LLM provider to use: anthropic | openai | gemini",
    ),
    limit: int = typer.Option(
        50,
        "--limit", "-l",
        help="Maximum number of alerts to pull (default: 50).",
        min=1,
    ),
    batch: int = typer.Option(
        10,
        "--batch", "-b",
        help="Number of alerts to triage per batch (default: 10).",
        min=1,
    ),
    format: Optional[str] = typer.Option(
        None,
        "--format", "-f",
        help="Output format: table (default) | json | html",
    ),
    output: Optional[str] = typer.Option(
        None,
        "--output", "-o",
        help="Save output to this file path (.json or .html).",
    ),
    # Wazuh options
    wazuh_url: Optional[str] = typer.Option(None, "--url", help="[Wazuh/Splunk] Base URL."),
    wazuh_user: Optional[str] = typer.Option(None, "--username", help="[Wazuh/Splunk] Username."),
    wazuh_password: Optional[str] = typer.Option(None, "--password", help="[Wazuh/Splunk] Password.", hide_input=True),
    wazuh_no_verify: bool = typer.Option(False, "--no-verify-ssl", help="[Wazuh/Splunk] Skip SSL verification."),
    # Sentinel options
    sentinel_sub: Optional[str] = typer.Option(None, "--subscription-id", help="[Sentinel] Azure subscription ID."),
    sentinel_rg: Optional[str] = typer.Option(None, "--resource-group", help="[Sentinel] Resource group name."),
    sentinel_ws: Optional[str] = typer.Option(None, "--workspace-name", help="[Sentinel] Log Analytics workspace name."),
    sentinel_tenant: Optional[str] = typer.Option(None, "--tenant-id", help="[Sentinel] Azure tenant ID."),
    sentinel_client: Optional[str] = typer.Option(None, "--client-id", help="[Sentinel] Service principal client ID."),
    sentinel_secret: Optional[str] = typer.Option(None, "--client-secret", help="[Sentinel] Service principal secret.", hide_input=True),
    # Splunk options
    splunk_query: Optional[str] = typer.Option(None, "--query", "-q", help="[Splunk] SPL search query."),
) -> None:
    """
    Pull alerts directly from a SIEM, triage them, and report verdicts.

    Examples:\n
      solsoc pull wazuh --url https://wazuh.example.com --limit 100\n
      solsoc pull sentinel --subscription-id xxx --resource-group rg --workspace-name ws\n
      solsoc pull splunk --url https://splunk.example.com:8089 --query "index=security"\n
      solsoc pull wazuh --url https://wazuh.example.com --format html --output report.html
    """
    from solsoc.config import (
        get_provider,
        get_wazuh_integration,
        get_sentinel_integration,
        get_splunk_integration,
    )
    from solsoc.triage.engine import run_triage

    siem = siem.lower()
    if siem not in ("wazuh", "sentinel", "splunk"):
        console.print(f"[bold red]Error:[/bold red] Unknown SIEM '{siem}'. Choose: wazuh | sentinel | splunk")
        raise typer.Exit(code=1)

    # 1 — Load LLM provider
    try:
        llm = get_provider(provider)
    except ValueError as exc:
        console.print(f"[bold red]Provider error:[/bold red] {exc}")
        raise typer.Exit(code=1)

    # 2 — Load SIEM integration
    try:
        if siem == "wazuh":
            integration = get_wazuh_integration(
                url=wazuh_url,
                username=wazuh_user,
                password=wazuh_password,
                verify_ssl=not wazuh_no_verify if wazuh_url else None,
            )
        elif siem == "sentinel":
            integration = get_sentinel_integration(
                subscription_id=sentinel_sub,
                resource_group=sentinel_rg,
                workspace_name=sentinel_ws,
                tenant_id=sentinel_tenant,
                client_id=sentinel_client,
                client_secret=sentinel_secret,
            )
        else:
            integration = get_splunk_integration(
                url=wazuh_url,
                username=wazuh_user,
                password=wazuh_password,
                query=splunk_query,
                verify_ssl=not wazuh_no_verify if wazuh_url else None,
            )
    except ValueError as exc:
        console.print(f"[bold red]Configuration error:[/bold red] {exc}")
        raise typer.Exit(code=1)

    # 3 — Fetch alerts
    console.print(f"[dim]Pulling up to {limit} alerts from [bold]{siem}[/bold]...[/dim]")
    try:
        alerts = integration.fetch_alerts(limit=limit)
    except Exception as exc:
        console.print(f"[bold red]Fetch error:[/bold red] {exc}")
        raise typer.Exit(code=1)

    if not alerts:
        console.print("[yellow]No alerts found.[/yellow]")
        raise typer.Exit(code=0)

    console.print(f"[dim]Pulled {len(alerts)} alert(s). Triaging with [bold]{provider}[/bold]...[/dim]")

    # 4 — Triage
    report = run_triage(alerts, llm, batch_size=batch)

    # 5 — Output
    _run_output(report, format, output)


@app.command()
def version() -> None:
    """Show SolSOC version."""
    from importlib.metadata import version as pkg_version
    try:
        v = pkg_version("solsoc")
    except Exception:
        v = "1.0.0-dev"
    typer.echo(f"SolSOC v{v}")


if __name__ == "__main__":
    app()
