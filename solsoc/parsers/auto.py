from __future__ import annotations

from solsoc.parsers.csv_parser import CSVParser
from solsoc.parsers.json_parser import JSONParser
from solsoc.triage.models import Alert


def detect_and_parse(content: str, hint: str | None = None) -> list[Alert]:
    """
    Auto-detect the format of the input content and parse it.
    hint: optional file extension ('json', 'csv') to skip detection.
    """
    if hint in ("json",):
        return JSONParser().parse(content)
    if hint in ("csv",):
        return CSVParser().parse(content)

    # Auto-detect: try JSON first, fall back to CSV
    stripped = content.strip()
    if stripped.startswith(("{", "[")):
        return JSONParser().parse(content)

    # Check if it looks like CSV (has a header row with commas)
    first_line = stripped.splitlines()[0] if stripped else ""
    if "," in first_line:
        return CSVParser().parse(content)

    # Last resort: try JSON anyway
    try:
        return JSONParser().parse(content)
    except Exception:
        raise ValueError(
            "Could not detect the alert format. "
            "Supported formats: JSON (generic, Wazuh, Sentinel), CSV (Splunk, generic). "
            "Pass --format json or --format csv to override auto-detection."
        )
