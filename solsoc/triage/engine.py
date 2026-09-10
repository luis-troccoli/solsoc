from __future__ import annotations

from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
)

from solsoc.llm.base import LLMProvider
from solsoc.triage.models import Alert, TriageReport, TriageResult


def _chunks(lst: list, n: int):
    """Split list into chunks of size n."""
    for i in range(0, len(lst), n):
        yield lst[i : i + n]


def run_triage(
    alerts: list[Alert],
    provider: LLMProvider,
    batch_size: int = 10,
) -> TriageReport:
    """
    Run triage on a list of alerts using the given LLM provider.
    Processes alerts in batches of batch_size to avoid rate-limit bursts.
    """
    results: list[TriageResult] = []
    batches = list(_chunks(alerts, batch_size))

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        transient=True,
    ) as progress:
        task = progress.add_task(
            f"Triaging {len(alerts)} alert(s) via {provider.name}...",
            total=len(alerts),
        )

        for batch in batches:
            for alert in batch:
                result = provider.triage(alert)
                results.append(result)
                progress.advance(task)

    true_positives = sum(1 for r in results if r.verdict == "TRUE_POSITIVE")
    false_positives = sum(1 for r in results if r.verdict == "FALSE_POSITIVE")
    needs_review = sum(1 for r in results if r.verdict == "NEEDS_REVIEW")

    return TriageReport(
        total=len(results),
        true_positives=true_positives,
        false_positives=false_positives,
        needs_review=needs_review,
        results=results,
        provider=provider.name,
    )
