from __future__ import annotations
import csv
import io
import uuid
from solsoc.parsers.base import BaseParser
from solsoc.triage.models import Alert

# Common column name mappings across SIEMs
_TITLE_FIELDS = ("title", "alertname", "alert_name", "name", "rule", "description")
_DESC_FIELDS = ("description", "message", "details", "full_log", "event_description")
_SEV_FIELDS = ("severity", "level", "priority", "risk_level", "urgency")
_ID_FIELDS = ("id", "_id", "alert_id", "event_id", "systemalertid")
_TS_FIELDS = ("timestamp", "time", "timegenerated", "date", "starttimeutc", "created_at")
_SRC_FIELDS = ("source", "source_system", "siem", "manager", "origin")


def _find(row: dict, candidates: tuple) -> str | None:
    lower = {k.lower(): v for k, v in row.items()}
    for c in candidates:
        if c in lower and lower[c]:
            return lower[c]
    return None


class CSVParser(BaseParser):
    """
    Parses CSV alert exports from Splunk, Sentinel, or any generic SIEM.
    Attempts to auto-map common column names.
    """

    def parse(self, content: str) -> list[Alert]:
        reader = csv.DictReader(io.StringIO(content))
        alerts = []
        for i, row in enumerate(reader):
            alert_id = _find(row, _ID_FIELDS) or str(uuid.uuid4())
            title = _find(row, _TITLE_FIELDS) or f"Alert #{i + 1}"
            alerts.append(Alert(
                id=alert_id,
                title=title,
                description=_find(row, _DESC_FIELDS),
                severity=_find(row, _SEV_FIELDS),
                source=_find(row, _SRC_FIELDS),
                timestamp=_find(row, _TS_FIELDS),
                raw=dict(row),
            ))
        return alerts
