from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from jinja2 import BaseLoader, Environment

from solsoc.triage.models import TriageReport

_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SolSOC — Triage Report</title>
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; font-size: 14px; background: #f5f5f5; color: #1a1a1a; padding: 2rem; }
  .container { max-width: 1200px; margin: 0 auto; }
  header { margin-bottom: 2rem; }
  header h1 { font-size: 22px; font-weight: 600; margin-bottom: 4px; }
  header p { color: #666; font-size: 13px; }
  .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 12px; margin-bottom: 2rem; }
  .stat { background: #fff; border: 0.5px solid #e0e0e0; border-radius: 10px; padding: 1rem 1.25rem; }
  .stat-label { font-size: 11px; font-weight: 500; text-transform: uppercase; letter-spacing: .05em; color: #888; margin-bottom: 4px; }
  .stat-value { font-size: 28px; font-weight: 600; }
  .stat-value.tp { color: #c0392b; }
  .stat-value.fp { color: #27ae60; }
  .stat-value.nr { color: #e67e22; }
  .stat-value.total { color: #2c3e50; }
  .card { background: #fff; border: 0.5px solid #e0e0e0; border-radius: 10px; overflow: hidden; }
  table { width: 100%; border-collapse: collapse; }
  thead th { background: #f8f8f8; font-size: 11px; font-weight: 600; text-transform: uppercase; letter-spacing: .05em; color: #666; padding: 10px 14px; text-align: left; border-bottom: 0.5px solid #e0e0e0; }
  tbody tr { border-bottom: 0.5px solid #f0f0f0; }
  tbody tr:last-child { border-bottom: none; }
  tbody tr:hover { background: #fafafa; }
  td { padding: 11px 14px; vertical-align: top; }
  .badge { display: inline-block; font-size: 11px; font-weight: 600; padding: 3px 8px; border-radius: 4px; white-space: nowrap; }
  .v-tp { background: #fde8e8; color: #a32d2d; }
  .v-fp { background: #e8f8ee; color: #1a6b3a; }
  .v-nr { background: #fef3e2; color: #854f0b; }
  .s-critical { background: #fde8e8; color: #a32d2d; }
  .s-high { background: #fde8e8; color: #c0392b; }
  .s-medium { background: #fef3e2; color: #854f0b; }
  .s-low { background: #e8f4fd; color: #185fa5; }
  .s-informational { background: #f0f0f0; color: #666; }
  .conf { font-weight: 600; }
  .conf-high { color: #27ae60; }
  .conf-mid { color: #e67e22; }
  .conf-low { color: #c0392b; }
  .mitre { font-family: monospace; font-size: 12px; color: #555; }
  .alert-id { font-family: monospace; font-size: 12px; color: #888; }
  .reason { color: #333; }
  .action { color: #555; font-style: italic; }
  footer { margin-top: 2rem; font-size: 12px; color: #aaa; text-align: center; }
</style>
</head>
<body>
<div class="container">
  <header>
    <h1>SolSOC — Alert Triage Report</h1>
    <p>Generated {{ generated_at }} &nbsp;·&nbsp; Provider: {{ report.provider }}</p>
  </header>

  <div class="stats">
    <div class="stat">
      <div class="stat-label">Total alerts</div>
      <div class="stat-value total">{{ report.total }}</div>
    </div>
    <div class="stat">
      <div class="stat-label">True positives</div>
      <div class="stat-value tp">{{ report.true_positives }}</div>
    </div>
    <div class="stat">
      <div class="stat-label">False positives</div>
      <div class="stat-value fp">{{ report.false_positives }}</div>
    </div>
    <div class="stat">
      <div class="stat-label">Needs review</div>
      <div class="stat-value nr">{{ report.needs_review }}</div>
    </div>
  </div>

  <div class="card">
    <table>
      <thead>
        <tr>
          <th>Alert ID</th>
          <th>Title</th>
          <th>Verdict</th>
          <th>Severity</th>
          <th>Confidence</th>
          <th>MITRE ATT&CK</th>
          <th>Reason</th>
          <th>Recommended action</th>
        </tr>
      </thead>
      <tbody>
        {% for r in report.results %}
        <tr>
          <td><span class="alert-id">{{ r.alert_id }}</span></td>
          <td>{{ r.alert_title }}</td>
          <td>
            {% if r.verdict == "TRUE_POSITIVE" %}
              <span class="badge v-tp">True positive</span>
            {% elif r.verdict == "FALSE_POSITIVE" %}
              <span class="badge v-fp">False positive</span>
            {% else %}
              <span class="badge v-nr">Needs review</span>
            {% endif %}
          </td>
          <td>
            <span class="badge s-{{ r.severity | lower }}">{{ r.severity | title }}</span>
          </td>
          <td>
            {% if r.confidence_score >= 80 %}
              <span class="conf conf-high">{{ r.confidence_score }}%</span>
            {% elif r.confidence_score >= 50 %}
              <span class="conf conf-mid">{{ r.confidence_score }}%</span>
            {% else %}
              <span class="conf conf-low">{{ r.confidence_score }}%</span>
            {% endif %}
          </td>
          <td><span class="mitre">{{ r.mitre_technique or "—" }}</span></td>
          <td><span class="reason">{{ r.reason }}</span></td>
          <td><span class="action">{{ r.recommended_action }}</span></td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
  </div>

  <footer>Generated by SolSOC &nbsp;·&nbsp; <a href="https://github.com/luis-troccoli/solsoc">github.com/luis-troccoli/solsoc</a></footer>
</div>
</body>
</html>"""


def render_html(report: TriageReport, output_path: str | None = None) -> str:
    """Render a triage report as an HTML file. Returns the HTML string."""
    env = Environment(loader=BaseLoader())
    template = env.from_string(_TEMPLATE)
    html = template.render(
        report=report,
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
    )
    if output_path:
        Path(output_path).write_text(html, encoding="utf-8")
    return html
