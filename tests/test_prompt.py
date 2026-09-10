from solsoc.triage.prompt import SYSTEM_PROMPT, build_user_prompt
from solsoc.triage.models import Alert


class TestSystemPrompt:
    def test_contains_confidence_score_field(self):
        assert "confidence_score" in SYSTEM_PROMPT

    def test_contains_mitre_field(self):
        assert "mitre_technique" in SYSTEM_PROMPT

    def test_contains_mitre_format_example(self):
        assert "T1110" in SYSTEM_PROMPT

    def test_contains_confidence_definitions(self):
        assert "90-100" in SYSTEM_PROMPT
        assert "0-29" in SYSTEM_PROMPT

    def test_contains_verdict_definitions(self):
        assert "TRUE_POSITIVE" in SYSTEM_PROMPT
        assert "FALSE_POSITIVE" in SYSTEM_PROMPT
        assert "NEEDS_REVIEW" in SYSTEM_PROMPT

    def test_instructs_json_only(self):
        assert "JSON" in SYSTEM_PROMPT


class TestBuildUserPrompt:
    def test_includes_id_and_title(self):
        alert = Alert(id="test-001", title="Brute force detected")
        prompt = build_user_prompt(alert)
        assert "test-001" in prompt
        assert "Brute force detected" in prompt

    def test_includes_optional_fields_when_present(self):
        alert = Alert(
            id="test-002",
            title="Test",
            source="Wazuh",
            severity="high",
            description="Some description",
            timestamp="2026-09-10T02:00:00Z",
        )
        prompt = build_user_prompt(alert)
        assert "Wazuh" in prompt
        assert "high" in prompt
        assert "Some description" in prompt
        assert "2026-09-10T02:00:00Z" in prompt

    def test_omits_none_fields(self):
        alert = Alert(id="test-003", title="Minimal alert")
        prompt = build_user_prompt(alert)
        assert "Source SIEM" not in prompt
        assert "Reported severity" not in prompt
        assert "Description" not in prompt
