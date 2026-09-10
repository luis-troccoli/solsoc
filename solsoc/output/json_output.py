from __future__ import annotations
import json
import sys
from pathlib import Path
from solsoc.triage.models import TriageReport


def print_json(report: TriageReport, output_path: str | None = None) -> None:
    """Output the triage report as clean JSON."""
    data = report.model_dump()
    formatted = json.dumps(data, indent=2)

    if output_path:
        Path(output_path).write_text(formatted, encoding="utf-8")
    else:
        sys.stdout.write(formatted + "\n")
