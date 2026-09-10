from __future__ import annotations

import uuid

import requests
import urllib3

from solsoc.integrations.base import SIEMIntegration
from solsoc.triage.models import Alert

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

_SEV_MAP = {
    "1": "INFORMATIONAL", "2": "INFORMATIONAL", "3": "INFORMATIONAL",
    "4": "LOW", "5": "LOW", "6": "LOW",
    "7": "MEDIUM", "8": "MEDIUM", "9": "MEDIUM",
    "10": "HIGH", "11": "HIGH", "12": "HIGH",
    "13": "CRITICAL", "14": "CRITICAL", "15": "CRITICAL",
}


class WazuhIntegration(SIEMIntegration):
    """
    Pulls alerts from the Wazuh REST API.

    Credentials (env vars or constructor args):
        WAZUH_URL      — e.g. https://wazuh.example.com:55000
        WAZUH_USER     — API username (default: wazuh-wui)
        WAZUH_PASSWORD — API password
        WAZUH_VERIFY_SSL — set to "false" to skip SSL verification (default: true)
    """

    name = "wazuh"

    def __init__(
        self,
        url: str,
        username: str,
        password: str,
        verify_ssl: bool = True,
    ) -> None:
        self.url = url.rstrip("/")
        self.username = username
        self.password = password
        self.verify_ssl = verify_ssl
        self._token: str | None = None

    def _authenticate(self) -> str:
        resp = requests.post(
            f"{self.url}/security/user/authenticate",
            auth=(self.username, self.password),
            verify=self.verify_ssl,
            timeout=15,
        )
        resp.raise_for_status()
        self._token = resp.json()["data"]["token"]
        return self._token

    def _headers(self) -> dict:
        if not self._token:
            self._authenticate()
        return {"Authorization": f"Bearer {self._token}"}

    def fetch_alerts(self, limit: int = 50) -> list[Alert]:
        resp = requests.get(
            f"{self.url}/alerts",
            headers=self._headers(),
            params={"limit": limit, "sort": "-timestamp"},
            verify=self.verify_ssl,
            timeout=30,
        )
        resp.raise_for_status()
        items = resp.json().get("data", {}).get("affected_items", [])
        return [self._normalize(item) for item in items]

    def _normalize(self, item: dict) -> Alert:
        rule = item.get("rule", {})
        item.get("agent", {})
        manager = item.get("manager", {})

        alert_id = item.get("id") or str(uuid.uuid4())
        title = rule.get("description") or rule.get("id") or "Wazuh Alert"
        description = item.get("full_log") or item.get("message")
        raw_level = str(rule.get("level", ""))
        severity = _SEV_MAP.get(raw_level, "MEDIUM")
        source = f"Wazuh ({manager.get('name', 'unknown')})"
        timestamp = item.get("timestamp")

        return Alert(
            id=str(alert_id),
            title=title,
            description=description,
            severity=severity,
            source=source,
            timestamp=timestamp,
            raw=item,
        )
