from __future__ import annotations

import time
import uuid

import requests
import urllib3

from solsoc.integrations.base import SIEMIntegration
from solsoc.triage.models import Alert

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

_SEV_MAP = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
    "info": "INFORMATIONAL",
    "informational": "INFORMATIONAL",
}

_DEFAULT_QUERY = 'search index=main sourcetype=alert earliest=-24h | head {limit}'


class SplunkIntegration(SIEMIntegration):
    """
    Pulls alerts from the Splunk REST API via a search job.

    Credentials (env vars or constructor args):
        SPLUNK_URL      — e.g. https://splunk.example.com:8089
        SPLUNK_USER     — Splunk username
        SPLUNK_PASSWORD — Splunk password
        SPLUNK_QUERY    — SPL query (optional, has a sensible default)
        SPLUNK_VERIFY_SSL — set to "false" to skip SSL verification (default: true)
    """

    name = "splunk"

    def __init__(
        self,
        url: str,
        username: str,
        password: str,
        query: str | None = None,
        verify_ssl: bool = True,
    ) -> None:
        self.url = url.rstrip("/")
        self.username = username
        self.password = password
        self.query = query
        self.verify_ssl = verify_ssl

    def _auth(self) -> dict:
        return {"username": self.username, "password": self.password}

    def fetch_alerts(self, limit: int = 50) -> list[Alert]:
        spl = (self.query or _DEFAULT_QUERY).replace("{limit}", str(limit))

        create_resp = requests.post(
            f"{self.url}/services/search/jobs",
            data={"search": spl, "output_mode": "json", "exec_mode": "normal"},
            auth=(self.username, self.password),
            verify=self.verify_ssl,
            timeout=30,
        )
        create_resp.raise_for_status()
        sid = create_resp.json()["sid"]

        for _ in range(30):
            status_resp = requests.get(
                f"{self.url}/services/search/jobs/{sid}",
                params={"output_mode": "json"},
                auth=(self.username, self.password),
                verify=self.verify_ssl,
                timeout=15,
            )
            status_resp.raise_for_status()
            dispatch_state = (
                status_resp.json()
                .get("entry", [{}])[0]
                .get("content", {})
                .get("dispatchState", "")
            )
            if dispatch_state == "DONE":
                break
            time.sleep(1)

        results_resp = requests.get(
            f"{self.url}/services/search/jobs/{sid}/results",
            params={"output_mode": "json", "count": limit},
            auth=(self.username, self.password),
            verify=self.verify_ssl,
            timeout=30,
        )
        results_resp.raise_for_status()
        items = results_resp.json().get("results", [])
        return [self._normalize(item) for item in items]

    def _normalize(self, item: dict) -> Alert:
        alert_id = (
            item.get("_cd")
            or item.get("event_id")
            or item.get("id")
            or str(uuid.uuid4())
        )
        title = (
            item.get("title")
            or item.get("alert_name")
            or item.get("source")
            or "Splunk Alert"
        )
        description = (
            item.get("description")
            or item.get("message")
            or item.get("_raw")
        )
        raw_sev = str(
            item.get("severity")
            or item.get("urgency")
            or item.get("risk_level")
            or ""
        ).lower()
        severity = _SEV_MAP.get(raw_sev, "MEDIUM")
        timestamp = item.get("_time") or item.get("timestamp")

        return Alert(
            id=str(alert_id),
            title=title,
            description=description,
            severity=severity,
            source="Splunk",
            timestamp=timestamp,
            raw=item,
        )
