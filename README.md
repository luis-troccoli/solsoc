<p align="center">
  <img src="assets/solsoc-logo.jpg" alt="SolSOC logo"/>
</p>

<p align="center">
  <strong>AI-powered SOC alert triage. Cut through the noise, surface what matters.</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.9%2B-3776AB?logo=python&logoColor=white" />
  <img src="https://img.shields.io/badge/license-MIT%20with%20Commons%20Clause-green" />
  <img src="https://github.com/luis-troccoli/solsoc/actions/workflows/ci.yml/badge.svg" />
  <img src="https://img.shields.io/github/v/release/luis-troccoli/solsoc" />
</p>

---

SolSOC is an open-source CLI that takes a batch of SIEM alerts, sends each one to an LLM of your choice, and returns a structured verdict: **TRUE_POSITIVE**, **FALSE_POSITIVE**, or **NEEDS_REVIEW** — with a severity assessment, a one-line reason, and a recommended next action.

No vendor lock-in. No enterprise license. You bring your own API key.

---

## The problem

SOC analysts face hundreds of alerts every shift. Most are false positives or low-value noise. Manually triaging each one is slow, repetitive, and exhausting — and it's exactly the kind of work that causes real threats to slip through.

Enterprise SIEMs like Splunk ES Premier and Microsoft Sentinel now ship AI triage agents — but they cost thousands per month and are locked to their own ecosystems.

SolSOC brings the same capability to any team, for free, regardless of which SIEM they use.

---

## Features

| Feature | Description |
|---|---|
| 🔍 Auto-detects format | Supports JSON and CSV — no flags needed for common exports |
| 🏢 Multi-SIEM | Works with Wazuh, Splunk, Microsoft Sentinel, or any generic export |
| 🔌 Direct SIEM pull | `solsoc pull wazuh/sentinel/splunk` — fetch, triage, and report in one command |
| 🤖 Multi-LLM | OpenAI, Anthropic (Claude), and Google Gemini — configurable per run |
| 📊 Structured verdicts | TRUE_POSITIVE / FALSE_POSITIVE / NEEDS_REVIEW with severity + reason + action |
| 🎯 MITRE ATT&CK mapping | Each alert is mapped to the most specific ATT&CK technique |
| 📈 Confidence score | 0–100% confidence per verdict, color-coded in terminal output |
| 🖥️ Rich terminal output | Color-coded table with summary stats and progress bar |
| 📄 JSON export | Machine-readable output for piping into scripts or SOAR playbooks |
| 🌐 HTML report | Shareable visual report for your team or manager (`--format html`) |
| 📦 Batch control | `--batch N` limits API calls per batch to avoid rate-limit bursts |
| 📥 stdin support | Pipe alerts directly: `cat alerts.json \| solsoc triage -` |

---

## Quick start

```bash
pip install solsoc
```

```bash
cp .env.example .env
# Edit .env and add your API key
```

```bash
solsoc triage alerts.json
```

That's it.

---

## Installation

### From PyPI (recommended)

```bash
pip install solsoc
```

### Microsoft Sentinel extras

```bash
pip install "solsoc[sentinel]"
```

### From source

```bash
git clone https://github.com/luis-troccoli/solsoc.git
cd solsoc
pip install -e .
```

---

## Configuration

Copy `.env.example` to `.env` and add at least one API key:

```env
ANTHROPIC_API_KEY="your_anthropic_key_here"
OPENAI_API_KEY="your_openai_key_here"
GEMINI_API_KEY="your_gemini_key_here"
```

Get your keys here:
- Anthropic — https://console.anthropic.com
- OpenAI — https://platform.openai.com
- Google Gemini — https://aistudio.google.com

---

## Usage

### Basic triage

```bash
# JSON file (auto-detects format)
solsoc triage alerts.json

# CSV export from Splunk
solsoc triage splunk_export.csv

# From stdin
cat alerts.json | solsoc triage -
```

### Choose your LLM

```bash
solsoc triage alerts.json --provider anthropic   # default
solsoc triage alerts.json --provider openai
solsoc triage alerts.json --provider gemini
```

### Export results

```bash
# JSON to stdout
solsoc triage alerts.json --format json

# Save JSON to file
solsoc triage alerts.json --format json --output results.json

# HTML report
solsoc triage alerts.json --format html --output report.html
```

### Control batch size

```bash
# 5 alerts per batch (default: 10)
solsoc triage alerts.json --batch 5

# One at a time — safest on rate limits
solsoc triage alerts.json --batch 1
```

---

## SIEM integrations

Pull alerts directly from your SIEM without exporting files first. SolSOC fetches, normalizes, triages, and reports in one step.

### Wazuh

```bash
# Via env vars (set WAZUH_URL, WAZUH_USER, WAZUH_PASSWORD in .env)
solsoc pull wazuh --limit 100

# Via CLI flags
solsoc pull wazuh --url https://wazuh.example.com:55000 --username wazuh-wui --password secret

# With HTML report
solsoc pull wazuh --url https://wazuh.example.com:55000 --format html --output report.html

# Skip SSL verification (self-signed certs)
solsoc pull wazuh --url https://wazuh.example.com:55000 --no-verify-ssl
```

**Required:** `WAZUH_URL`, `WAZUH_USER`, `WAZUH_PASSWORD`
**Optional:** `WAZUH_VERIFY_SSL` (default: `true`)

---

### Microsoft Sentinel

```bash
# Via env vars (set SENTINEL_SUBSCRIPTION_ID, SENTINEL_RESOURCE_GROUP, SENTINEL_WORKSPACE_NAME in .env)
solsoc pull sentinel --limit 50

# Via CLI flags
solsoc pull sentinel \
  --subscription-id your-sub-id \
  --resource-group your-rg \
  --workspace-name your-workspace

# With service principal (CI/CD — no az CLI session needed)
solsoc pull sentinel \
  --subscription-id your-sub-id \
  --resource-group your-rg \
  --workspace-name your-workspace \
  --tenant-id your-tenant \
  --client-id your-client-id \
  --client-secret your-secret
```

**Required:** `SENTINEL_SUBSCRIPTION_ID`, `SENTINEL_RESOURCE_GROUP`, `SENTINEL_WORKSPACE_NAME`
**Optional:** `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET` (falls back to `az login` if not set)

---

### Splunk

```bash
# Via env vars (set SPLUNK_URL, SPLUNK_USER, SPLUNK_PASSWORD in .env)
solsoc pull splunk --limit 100

# Via CLI flags
solsoc pull splunk \
  --url https://splunk.example.com:8089 \
  --username admin \
  --password secret

# Custom SPL query
solsoc pull splunk \
  --url https://splunk.example.com:8089 \
  --query 'search index=security sourcetype=alert severity=high earliest=-1h'
```

**Required:** `SPLUNK_URL`, `SPLUNK_USER`, `SPLUNK_PASSWORD`
**Optional:** `SPLUNK_QUERY` (default: `index=main` last 24h), `SPLUNK_VERIFY_SSL`

---

## Output

### Terminal

Wazuh alerts:

![SolSOC terminal output — Wazuh](assets/wazuh-report-screenshot.png)

Sentinel alerts:

![SolSOC terminal output — Sentinel](assets/sentinel-report-screenshot.png)

### HTML report

```bash
solsoc triage alerts.json --format html --output report.html
```

![SolSOC HTML report](assets/html-report-screenshot.png)

### JSON

```json
{
  "total": 5,
  "true_positives": 2,
  "false_positives": 1,
  "needs_review": 2,
  "provider": "anthropic",
  "results": [
    {
      "alert_id": "wazuh-001",
      "alert_title": "Brute force attack detected",
      "verdict": "TRUE_POSITIVE",
      "severity": "HIGH",
      "reason": "15 failed SSH attempts in 30 seconds from an external IP is consistent with a real brute-force attack.",
      "recommended_action": "Block the source IP at the firewall and review authentication logs for any successful logins.",
      "confidence_score": 94,
      "mitre_technique": "T1110 - Brute Force",
      "provider": "anthropic",
      "error": null
    }
  ]
}
```

---

## Example files

The `examples/` folder has ready-to-use alert files so you can test SolSOC without a real SIEM:

```bash
solsoc triage examples/wazuh_alerts.json
solsoc triage examples/splunk_alerts.csv
solsoc triage examples/sentinel_alerts.json
```

---

## Command reference

### `solsoc triage`

```
solsoc triage <source> [options]
```

| Option | Description | Default |
|---|---|---|
| `source` | Alert file (JSON/CSV) or `-` for stdin | required |
| `--provider`, `-p` | `anthropic` \| `openai` \| `gemini` | `anthropic` |
| `--format`, `-f` | `table` \| `json` \| `html` | `table` |
| `--output`, `-o` | Save to file (`.json` or `.html`) | stdout |
| `--input-format` | Force `json` or `csv` (skips auto-detect) | auto |
| `--batch`, `-b` | Alerts per batch | `10` |

---

### `solsoc pull`

```
solsoc pull <siem> [options]
```

| Option | Description | Default |
|---|---|---|
| `siem` | `wazuh` \| `sentinel` \| `splunk` | required |
| `--provider`, `-p` | `anthropic` \| `openai` \| `gemini` | `anthropic` |
| `--limit`, `-l` | Max alerts to pull | `50` |
| `--batch`, `-b` | Alerts per triage batch | `10` |
| `--format`, `-f` | `table` \| `json` \| `html` | `table` |
| `--output`, `-o` | Save to file | stdout |

**Wazuh / Splunk flags:** `--url`, `--username`, `--password`, `--no-verify-ssl`
**Sentinel flags:** `--subscription-id`, `--resource-group`, `--workspace-name`, `--tenant-id`, `--client-id`, `--client-secret`
**Splunk only:** `--query`, `-q`

---

### `solsoc version`

```bash
solsoc version
```

---

## Cost

SolSOC doesn't charge anything — you pay only for the LLM API calls you make, billed directly by your provider.

As a reference: triaging 5 alerts with Claude Sonnet costs roughly **$0.04 per run** (~$0.008 per alert). A full shift of 50 alerts would cost around **$0.40**.

Costs vary by provider — Gemini Flash and GPT-4o Mini are significantly cheaper if budget is a concern.

---

## Contributing

Contributions are welcome — bug reports, feature suggestions, and code fixes. Read [`CONTRIBUTING.md`](./CONTRIBUTING.md) before submitting a PR.

By contributing, you agree to the Contributor License Agreement in [`LICENSE`](./LICENSE).

```bash
git clone https://github.com/luis-troccoli/solsoc.git
cd solsoc
pip install -e ".[dev]"
pytest tests/
```

---

## License

MIT with Commons Clause — free to use and distribute. You may not sell this software or offer it as a hosted service without explicit written permission from the author.

For commercial licensing: ltrocc@gmail.com

---

*Built by [Luis Troccoli](https://github.com/luis-troccoli) — Cloud Security Engineer / DevSecOps.*
*If SolSOC saves you time, give it a ⭐ — it helps others find it.*
