from __future__ import annotations

import json
import uuid

from solsoc.parsers.base import BaseParser
from solsoc.triage.models import Alert


class JSONParser(BaseParser):
    """
    Parses JSON alerts from multiple sources:
    - Generic JSON array of alert objects
    - Wazuh JSON alerts (single object or array)
    - Microsoft Sentinel JSON export
    """

    def parse(self, content: str) -> list[Alert]:
        data = json.loads(content)

        # Normalize to list
        if isinstance(data, dict):
            # Sentinel wraps alerts in {"value": [...]}
            if "value" in data and isinstance(data["value"], list):
                items = data["value"]
            else:
                items = [data]
        elif isinstance(data, list):
            items = data
        else:
            raise ValueError("JSON content must be an object or array of alerts.")

        return [self._normalize(item) for item in items]

    def _normalize(self, item: dict) -> Alert:
        # Try to detect and map common SIEM field names
        alert_id = (
            str(item.get("id") or item.get("_id") or item.get("SystemAlertId") or uuid.uuid4())
        )

        rule = item.get("rule")
        manager = item.get("manager")

        title = (
            item.get("title")
            or item.get("AlertDisplayName")
            or (rule.get("name") if isinstance(rule, dict) else None)
            or item.get("name")
            or "Untitled Alert"
        )

        description = (
            item.get("description")
            or item.get("Description")
            or item.get("full_log")
        )

        severity = (
            item.get("severity")
            or item.get("Severity")
            or item.get("level")
        )

        # Detect source SIEM
        source = (
            item.get("source")
            or (manager.get("name") if isinstance(manager, dict) else None)
        )
        if not source:
            if "SystemAlertId" in item or "WorkspaceSubscriptionId" in item:
                source = "Microsoft Sentinel"
            elif "agent" in item and "manager" in item:
                source = "Wazuh"

        timestamp = (
            item.get("timestamp")
            or item.get("TimeGenerated")
            or item.get("StartTimeUtc")
        )

        return Alert(
            id=alert_id,
            title=str(title),
            description=str(description) if description else None,
            severity=str(severity) if severity else None,
            source=str(source) if source else None,
            timestamp=str(timestamp) if timestamp else None,
            raw=item,
        )
