import pytest
from pydantic import ValidationError
from solsoc.triage.models import TriageResult, TriageReport, Alert


def _make_result(**kwargs) -> TriageResult:
    defaults = dict(
        alert_id="test-001",
        alert_title="Test alert",
        verdict="TRUE_POSITIVE",
        severity="HIGH",
        reason="Test reason",
        recommended_action="Test action",
        confidence_score=85,
        mitre_technique="T1110 - Brute Force",
        provider="test",
    )
    defaults.update(kwargs)
    return TriageResult(**defaults)


class TestConfidenceScore:
    def test_valid_score(self):
        r = _make_result(confidence_score=75)
        assert r.confidence_score == 75

    def test_mitre_technique_optional(self):
        r = _make_result(mitre_technique=None)
        assert r.mitre_technique is None

    def test_mitre_technique_stored(self):
        r = _make_result(mitre_technique="T1059 - Command and Scripting Interpreter")
        assert r.mitre_technique == "T1059 - Command and Scripting Interpreter"

    def test_boundary_zero(self):
        r = _make_result(confidence_score=0)
        assert r.confidence_score == 0

    def test_boundary_hundred(self):
        r = _make_result(confidence_score=100)
        assert r.confidence_score == 100

    def test_above_range_raises(self):
        with pytest.raises(ValidationError):
            _make_result(confidence_score=101)

    def test_below_range_raises(self):
        with pytest.raises(ValidationError):
            _make_result(confidence_score=-1)


class TestTriageReport:
    def test_report_counts(self):
        results = [
            _make_result(alert_id="a1", verdict="TRUE_POSITIVE"),
            _make_result(alert_id="a2", verdict="FALSE_POSITIVE"),
            _make_result(alert_id="a3", verdict="NEEDS_REVIEW"),
        ]
        report = TriageReport(
            total=3,
            true_positives=1,
            false_positives=1,
            needs_review=1,
            results=results,
            provider="test",
        )
        assert report.total == 3
        assert report.true_positives == 1
        assert report.false_positives == 1
        assert report.needs_review == 1
