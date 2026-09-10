from __future__ import annotations
import pytest
from unittest.mock import MagicMock, patch
from solsoc.integrations.wazuh import WazuhIntegration
from solsoc.integrations.splunk import SplunkIntegration
from solsoc.integrations.sentinel import SentinelIntegration
from solsoc.triage.models import Alert


WAZUH_ITEM = {
    "id": "1748392010.12345",
    "timestamp": "2026-09-10T02:14:33.812Z",
    "rule": {
        "id": "5710",
        "description": "Multiple authentication failures",
        "level": 10,
    },
    "agent": {"id": "003", "name": "web-server-01"},
    "manager": {"name": "wazuh-manager"},
    "full_log": "sshd: Multiple authentication failures from 203.0.113.45",
}

SPLUNK_ITEM = {
    "_cd": "splunk-001",
    "_time": "2026-09-10T03:01:00Z",
    "title": "Brute force login attempt",
    "description": "50 failed logins for admin from 203.0.113.99",
    "severity": "high",
    "source": "Splunk",
}


class TestWazuhNormalize:
    def setup_method(self):
        self.integration = WazuhIntegration(
            url="https://fake", username="user", password="pass"
        )

    def test_normalizes_id(self):
        alert = self.integration._normalize(WAZUH_ITEM)
        assert alert.id == "1748392010.12345"

    def test_normalizes_title_from_rule_description(self):
        alert = self.integration._normalize(WAZUH_ITEM)
        assert alert.title == "Multiple authentication failures"

    def test_maps_level_10_to_high(self):
        alert = self.integration._normalize(WAZUH_ITEM)
        assert alert.severity == "HIGH"

    def test_source_includes_manager(self):
        alert = self.integration._normalize(WAZUH_ITEM)
        assert "wazuh-manager" in alert.source

    def test_timestamp_preserved(self):
        alert = self.integration._normalize(WAZUH_ITEM)
        assert alert.timestamp == "2026-09-10T02:14:33.812Z"

    def test_raw_preserved(self):
        alert = self.integration._normalize(WAZUH_ITEM)
        assert alert.raw == WAZUH_ITEM

    def test_level_1_to_informational(self):
        item = {**WAZUH_ITEM, "rule": {"level": 1, "description": "Test"}}
        alert = self.integration._normalize(item)
        assert alert.severity == "INFORMATIONAL"

    def test_level_15_to_critical(self):
        item = {**WAZUH_ITEM, "rule": {"level": 15, "description": "Test"}}
        alert = self.integration._normalize(item)
        assert alert.severity == "CRITICAL"

    def test_missing_id_generates_uuid(self):
        item = {k: v for k, v in WAZUH_ITEM.items() if k != "id"}
        alert = self.integration._normalize(item)
        assert alert.id != ""
        assert len(alert.id) > 0


class TestSplunkNormalize:
    def setup_method(self):
        self.integration = SplunkIntegration(
            url="https://fake:8089", username="user", password="pass"
        )

    def test_normalizes_id(self):
        alert = self.integration._normalize(SPLUNK_ITEM)
        assert alert.id == "splunk-001"

    def test_normalizes_title(self):
        alert = self.integration._normalize(SPLUNK_ITEM)
        assert alert.title == "Brute force login attempt"

    def test_maps_high_severity(self):
        alert = self.integration._normalize(SPLUNK_ITEM)
        assert alert.severity == "HIGH"

    def test_maps_critical_severity(self):
        item = {**SPLUNK_ITEM, "severity": "critical"}
        alert = self.integration._normalize(item)
        assert alert.severity == "CRITICAL"

    def test_maps_info_severity(self):
        item = {**SPLUNK_ITEM, "severity": "info"}
        alert = self.integration._normalize(item)
        assert alert.severity == "INFORMATIONAL"

    def test_unknown_severity_defaults_medium(self):
        item = {**SPLUNK_ITEM, "severity": "unknown_value"}
        alert = self.integration._normalize(item)
        assert alert.severity == "MEDIUM"

    def test_source_is_splunk(self):
        alert = self.integration._normalize(SPLUNK_ITEM)
        assert alert.source == "Splunk"

    def test_timestamp_preserved(self):
        alert = self.integration._normalize(SPLUNK_ITEM)
        assert alert.timestamp == "2026-09-10T03:01:00Z"

    def test_raw_preserved(self):
        alert = self.integration._normalize(SPLUNK_ITEM)
        assert alert.raw == SPLUNK_ITEM

    def test_missing_id_generates_uuid(self):
        item = {k: v for k, v in SPLUNK_ITEM.items() if k not in ("_cd", "event_id", "id")}
        alert = self.integration._normalize(item)
        assert alert.id != ""


class TestSentinelNormalize:
    def setup_method(self):
        self.integration = SentinelIntegration(
            subscription_id="sub-123",
            resource_group="rg-test",
            workspace_name="ws-test",
        )

    def _mock_incident(self, **overrides):
        props = MagicMock()
        props.title = overrides.get("title", "Suspicious sign-in")
        props.description = overrides.get("description", "Sign-in from unusual location")
        props.severity = overrides.get("severity", "High")
        props.created_time_utc = overrides.get("created_time_utc", "2026-09-10T04:00:00Z")
        props.status = overrides.get("status", "New")
        incident = MagicMock()
        incident.name = overrides.get("name", "sentinel-001")
        incident.id = overrides.get("id", "/subscriptions/sub-123/incidents/sentinel-001")
        incident.properties = props
        return incident

    def test_normalizes_id(self):
        alert = self.integration._normalize(self._mock_incident())
        assert alert.id == "sentinel-001"

    def test_normalizes_title(self):
        alert = self.integration._normalize(self._mock_incident())
        assert alert.title == "Suspicious sign-in"

    def test_maps_high_severity(self):
        alert = self.integration._normalize(self._mock_incident(severity="High"))
        assert alert.severity == "HIGH"

    def test_maps_medium_severity(self):
        alert = self.integration._normalize(self._mock_incident(severity="Medium"))
        assert alert.severity == "MEDIUM"

    def test_maps_low_severity(self):
        alert = self.integration._normalize(self._mock_incident(severity="Low"))
        assert alert.severity == "LOW"

    def test_maps_informational_severity(self):
        alert = self.integration._normalize(self._mock_incident(severity="Informational"))
        assert alert.severity == "INFORMATIONAL"

    def test_source_is_sentinel(self):
        alert = self.integration._normalize(self._mock_incident())
        assert alert.source == "Microsoft Sentinel"

    def test_timestamp_preserved(self):
        alert = self.integration._normalize(self._mock_incident())
        assert "2026-09-10" in alert.timestamp
