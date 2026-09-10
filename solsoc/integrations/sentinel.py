from __future__ import annotations
import uuid
from solsoc.integrations.base import SIEMIntegration
from solsoc.triage.models import Alert

_SEV_MAP = {
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
    "informational": "INFORMATIONAL",
}


class SentinelIntegration(SIEMIntegration):
    """
    Pulls incidents from Microsoft Sentinel via the Azure SDK.

    Credentials (env vars or constructor args):
        SENTINEL_SUBSCRIPTION_ID — Azure subscription ID
        SENTINEL_RESOURCE_GROUP  — resource group name
        SENTINEL_WORKSPACE_NAME  — Log Analytics workspace name
        AZURE_TENANT_ID          — used by DefaultAzureCredential
        AZURE_CLIENT_ID          — used by DefaultAzureCredential (service principal)
        AZURE_CLIENT_SECRET      — used by DefaultAzureCredential (service principal)

    Auth falls back to az CLI session if service principal vars are not set.
    """

    name = "sentinel"

    def __init__(
        self,
        subscription_id: str,
        resource_group: str,
        workspace_name: str,
        tenant_id: str | None = None,
        client_id: str | None = None,
        client_secret: str | None = None,
    ) -> None:
        self.subscription_id = subscription_id
        self.resource_group = resource_group
        self.workspace_name = workspace_name
        self._tenant_id = tenant_id
        self._client_id = client_id
        self._client_secret = client_secret

    def _get_credential(self):
        if self._tenant_id and self._client_id and self._client_secret:
            from azure.identity import ClientSecretCredential
            return ClientSecretCredential(
                tenant_id=self._tenant_id,
                client_id=self._client_id,
                client_secret=self._client_secret,
            )
        from azure.identity import DefaultAzureCredential
        return DefaultAzureCredential()

    def fetch_alerts(self, limit: int = 50) -> list[Alert]:
        from azure.mgmt.securityinsight import SecurityInsights

        client = SecurityInsights(
            credential=self._get_credential(),
            subscription_id=self.subscription_id,
        )
        incidents = client.incidents.list(
            resource_group_name=self.resource_group,
            workspace_name=self.workspace_name,
        )
        alerts = []
        for i, incident in enumerate(incidents):
            if i >= limit:
                break
            alerts.append(self._normalize(incident))
        return alerts

    def _normalize(self, incident) -> Alert:
        props = incident.properties if hasattr(incident, "properties") else {}

        alert_id = incident.name or str(uuid.uuid4())
        title = getattr(props, "title", None) or "Sentinel Incident"
        description = getattr(props, "description", None)
        raw_sev = str(getattr(props, "severity", "")).lower()
        severity = _SEV_MAP.get(raw_sev, "MEDIUM")
        timestamp = str(getattr(props, "created_time_utc", "")) or None
        status = getattr(props, "status", "")

        return Alert(
            id=str(alert_id),
            title=title,
            description=description,
            severity=severity,
            source="Microsoft Sentinel",
            timestamp=timestamp,
            raw={
                "id": incident.id,
                "name": incident.name,
                "status": str(status),
                "severity": raw_sev,
                "title": title,
                "description": description,
                "created_time_utc": timestamp,
            },
        )
