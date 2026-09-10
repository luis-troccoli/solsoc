# Changelog

All notable changes to SolSOC are documented here.

## [1.0.0] — 2026-09-10

### Added
- **Wazuh API integration** (`solsoc pull wazuh`) — pull alerts directly from Wazuh REST API. Authenticates via Bearer token, maps rule levels (1–15) to severity, supports SSL verification toggle.
- **Microsoft Sentinel integration** (`solsoc pull sentinel`) — pull incidents via Azure SDK. Supports both service principal (tenant/client/secret) and `az login` session (DefaultAzureCredential). Install Azure extras with `pip install "solsoc[sentinel]"`.
- **Splunk integration** (`solsoc pull splunk`) — pull results via Splunk REST API using async search jobs. Supports custom SPL queries via `--query` or `SPLUNK_QUERY` env var.
- **`solsoc pull` command** — new CLI subcommand that fetches, triages, and reports in one step. Supports all output formats (`table`, `json`, `html`) and `--batch` control.
- All credentials configurable via `.env` file or CLI flags (CLI overrides `.env`).
- 27 new unit tests (71 total, all passing).

## [0.3.0] — 2026-09-10

### Added
- **MITRE ATT&CK mapping** — each alert is now mapped to the most specific ATT&CK technique (e.g. `T1110.001 - Password Guessing`). Shown in terminal output and HTML report. Set to `null` for false positives or alerts with no applicable technique.
- **HTML report output** (`--format html`, `--output report.html`) — a self-contained, shareable HTML file with a summary stats row and a full color-coded results table. Auto-detected from `.html` file extension on `--output`.
- 11 new unit tests (44 total, all passing).

## [0.2.0] — 2026-09-10

### Added
- **Batch size control** (`--batch N`, default: 10) — limits how many alerts are sent to the LLM per batch, preventing rate-limit bursts on large alert sets. Use `--batch 1` for the safest mode.
- **Confidence score** — the LLM now returns a 0–100 confidence score alongside each verdict. Shown as a color-coded column in the terminal output (green ≥80%, yellow 50–79%, red <50%) and included in JSON export.
- **Progress bar** — Rich progress bar displays real-time triage progress when processing multiple alerts.
- 22 new unit tests (33 total, all passing).

## [0.1.0] — 2026-09-09

### Initial release
- AI-powered SOC alert triage via CLI (`solsoc triage <file>`)
- Auto-detects JSON and CSV alert formats (Wazuh, Splunk, Microsoft Sentinel, generic)
- Supports OpenAI, Anthropic (Claude), and Google Gemini — configurable via `--provider`
- Verdict per alert: `TRUE_POSITIVE`, `FALSE_POSITIVE`, or `NEEDS_REVIEW`
- Severity assessment independent from the SIEM's reported severity
- Rich terminal table output and JSON export (`--format json`, `--output <file>`)
- stdin support: `cat alerts.json | solsoc triage -`
- Example alert files for Wazuh, Splunk, and Microsoft Sentinel in `examples/`
- GitHub Actions CI (Python 3.9–3.12 matrix + ruff lint)
- MIT with Commons Clause license
