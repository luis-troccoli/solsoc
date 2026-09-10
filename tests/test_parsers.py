import json
import pytest
from solsoc.parsers.auto import detect_and_parse
from solsoc.parsers.json_parser import JSONParser
from solsoc.parsers.csv_parser import CSVParser


SAMPLE_JSON = json.dumps([
    {
        "id": "alert-001",
        "title": "Brute force attack detected",
        "description": "Multiple failed SSH login attempts",
        "severity": "high",
        "source": "Wazuh",
        "timestamp": "2026-09-10T02:14:00Z",
    },
    {
        "id": "alert-002",
        "title": "Port scan detected",
        "severity": "medium",
        "source": "Suricata",
    },
])

SAMPLE_CSV = """id,title,severity,source,description
alert-001,Brute force attack detected,high,Wazuh,Multiple failed SSH login attempts
alert-002,Port scan detected,medium,Suricata,Nmap scan detected
"""

SAMPLE_SENTINEL = json.dumps({
    "value": [
        {
            "SystemAlertId": "sentinel-001",
            "AlertDisplayName": "Suspicious sign-in activity",
            "Severity": "High",
            "TimeGenerated": "2026-09-10T02:14:00Z",
            "Description": "Sign-in from unusual location",
        }
    ]
})


class TestJSONParser:
    def test_parses_array(self):
        alerts = JSONParser().parse(SAMPLE_JSON)
        assert len(alerts) == 2
        assert alerts[0].id == "alert-001"
        assert alerts[0].title == "Brute force attack detected"
        assert alerts[0].severity == "high"
        assert alerts[0].source == "Wazuh"

    def test_parses_sentinel_format(self):
        alerts = JSONParser().parse(SAMPLE_SENTINEL)
        assert len(alerts) == 1
        assert alerts[0].id == "sentinel-001"
        assert alerts[0].title == "Suspicious sign-in activity"
        assert alerts[0].source == "Microsoft Sentinel"

    def test_raw_is_preserved(self):
        alerts = JSONParser().parse(SAMPLE_JSON)
        assert alerts[0].raw["id"] == "alert-001"

    def test_missing_fields_get_none(self):
        alerts = JSONParser().parse(SAMPLE_JSON)
        assert alerts[1].description is None


class TestCSVParser:
    def test_parses_csv(self):
        alerts = CSVParser().parse(SAMPLE_CSV)
        assert len(alerts) == 2
        assert alerts[0].title == "Brute force attack detected"
        assert alerts[0].severity == "high"
        assert alerts[0].source == "Wazuh"

    def test_raw_is_preserved(self):
        alerts = CSVParser().parse(SAMPLE_CSV)
        assert "title" in alerts[0].raw


class TestAutoDetect:
    def test_detects_json(self):
        alerts = detect_and_parse(SAMPLE_JSON)
        assert len(alerts) == 2

    def test_detects_csv(self):
        alerts = detect_and_parse(SAMPLE_CSV)
        assert len(alerts) == 2

    def test_hint_forces_json(self):
        alerts = detect_and_parse(SAMPLE_JSON, hint="json")
        assert len(alerts) == 2

    def test_hint_forces_csv(self):
        alerts = detect_and_parse(SAMPLE_CSV, hint="csv")
        assert len(alerts) == 2

    def test_invalid_raises(self):
        with pytest.raises(ValueError):
            detect_and_parse("this is not valid alert data at all!!!")
