import pytest
from solsoc.triage.engine import run_triage, _chunks
from solsoc.triage.models import Alert, TriageResult
from solsoc.llm.base import LLMProvider


class MockProvider(LLMProvider):
    """Mock LLM provider that returns a fixed verdict without calling any API."""
    name = "mock"

    def triage(self, alert: Alert) -> TriageResult:
        return TriageResult(
            alert_id=alert.id,
            alert_title=alert.title,
            verdict="TRUE_POSITIVE",
            severity="HIGH",
            reason="Mock reason",
            recommended_action="Mock action",
            confidence_score=90,
            mitre_technique="T1110 - Brute Force",
            provider=self.name,
        )


def _make_alerts(n: int) -> list[Alert]:
    return [
        Alert(id=f"alert-{i:03d}", title=f"Alert {i}")
        for i in range(n)
    ]


class TestChunks:
    def test_even_split(self):
        chunks = list(_chunks(list(range(10)), 5))
        assert len(chunks) == 2
        assert chunks[0] == [0, 1, 2, 3, 4]
        assert chunks[1] == [5, 6, 7, 8, 9]

    def test_uneven_split(self):
        chunks = list(_chunks(list(range(7)), 3))
        assert len(chunks) == 3
        assert chunks[2] == [6]

    def test_batch_larger_than_list(self):
        chunks = list(_chunks(list(range(3)), 10))
        assert len(chunks) == 1
        assert chunks[0] == [0, 1, 2]

    def test_empty_list(self):
        assert list(_chunks([], 5)) == []


class TestRunTriage:
    def test_processes_all_alerts(self):
        alerts = _make_alerts(5)
        report = run_triage(alerts, MockProvider(), batch_size=2)
        assert report.total == 5
        assert len(report.results) == 5

    def test_counts_are_correct(self):
        alerts = _make_alerts(3)
        report = run_triage(alerts, MockProvider())
        assert report.true_positives == 3
        assert report.false_positives == 0
        assert report.needs_review == 0

    def test_batch_size_one(self):
        alerts = _make_alerts(4)
        report = run_triage(alerts, MockProvider(), batch_size=1)
        assert report.total == 4

    def test_confidence_scores_present(self):
        alerts = _make_alerts(3)
        report = run_triage(alerts, MockProvider())
        for result in report.results:
            assert 0 <= result.confidence_score <= 100

    def test_provider_name_in_report(self):
        alerts = _make_alerts(2)
        report = run_triage(alerts, MockProvider())
        assert report.provider == "mock"
