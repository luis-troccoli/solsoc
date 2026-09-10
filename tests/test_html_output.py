from solsoc.output.html_output import render_html
from solsoc.triage.models import TriageReport, TriageResult


def _make_report() -> TriageReport:
    results = [
        TriageResult(
            alert_id="alert-001",
            alert_title="Brute force attack",
            verdict="TRUE_POSITIVE",
            severity="HIGH",
            reason="Multiple failed SSH logins from external IP.",
            recommended_action="Block source IP immediately.",
            confidence_score=92,
            mitre_technique="T1110 - Brute Force",
            provider="mock",
        ),
        TriageResult(
            alert_id="alert-002",
            alert_title="AV definition update",
            verdict="FALSE_POSITIVE",
            severity="INFORMATIONAL",
            reason="Routine antivirus update — no threat.",
            recommended_action="No action needed.",
            confidence_score=98,
            mitre_technique=None,
            provider="mock",
        ),
    ]
    return TriageReport(
        total=2,
        true_positives=1,
        false_positives=1,
        needs_review=0,
        results=results,
        provider="mock",
    )


class TestHtmlOutput:
    def test_renders_html(self):
        html = render_html(_make_report())
        assert "<!DOCTYPE html>" in html
        assert "SolSOC" in html

    def test_contains_alert_ids(self):
        html = render_html(_make_report())
        assert "alert-001" in html
        assert "alert-002" in html

    def test_contains_verdicts(self):
        html = render_html(_make_report())
        assert "True positive" in html
        assert "False positive" in html

    def test_contains_mitre(self):
        html = render_html(_make_report())
        assert "T1110 - Brute Force" in html

    def test_mitre_null_shows_dash(self):
        html = render_html(_make_report())
        assert "—" in html

    def test_contains_stats(self):
        html = render_html(_make_report())
        assert "Total alerts" in html
        assert "True positives" in html
        assert "False positives" in html

    def test_writes_to_file(self, tmp_path):
        out = tmp_path / "report.html"
        render_html(_make_report(), output_path=str(out))
        assert out.exists()
        assert "SolSOC" in out.read_text()
