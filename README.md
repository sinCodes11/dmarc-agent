# DMARC Security Agent

A CLI tool and automation stack for auditing and enforcing email authentication (SPF, DKIM, DMARC) across client domains.

Designed for security consultants and IT administrators managing email security for small-to-medium businesses.

---

## What It Does

- Queries live DNS records and analyzes SPF, DKIM, and DMARC configuration
- Classifies risk as **HIGH / MEDIUM / LOW** with detailed justification
- Generates copy-paste-ready DNS records following a safe, staged rollout
- Produces HTML, JSON, or terminal reports for clients and records
- Parses incoming DMARC aggregate report files (`.xml`, `.xml.gz`, `.zip`)
- Exposes a REST API for integration with n8n or other automation platforms
- Includes 5 ready-to-import n8n workflows for scheduled scanning, report ingestion, alerting, and batch analysis

---

## Quick Start

```bash
# Clone the repo
git clone https://github.com/sinCodes11/dmarc-agent.git
cd dmarc-agent

# Install (requires Python 3.10+)
pip install -e "src/[api]"

# Verify
dmarc-agent --version
```

---

## CLI Usage

```bash
# Full domain analysis (terminal output)
dmarc-agent analyze example.com

# With a known DKIM selector
dmarc-agent analyze example.com --dkim-selector google

# Save HTML report for client delivery
dmarc-agent analyze example.com --format html --output report.html

# Save JSON for scripting or records
dmarc-agent analyze example.com --format json --output result.json

# Check SPF only
dmarc-agent check-spf example.com

# Check DMARC only
dmarc-agent check-dmarc example.com

# Verify a DKIM selector
dmarc-agent verify-dkim selector1 example.com

# Parse an aggregate DMARC report file
dmarc-agent parse-report report.xml.gz
dmarc-agent parse-report report.xml.gz --format json

# Start the REST API server (for n8n automation)
DMARC_API_KEY=your-secret-key dmarc-agent serve --port 8000
```

---

## Output Example

```
╭─────────────────────────────────────────────────╮
│         SECURITY ANALYSIS: example.com          │
╰─────────────────────────────────────────────────╯

SECURITY STATUS
  SPF Record:          Present — Softfail (~all)
  DKIM:                Not detected
  DMARC Record:        Absent
  Aggregate Reporting: Not configured

RISK LEVEL:  HIGH RISK

ISSUES FOUND
  1. No DMARC record — receivers have no policy for handling failures
  2. SPF uses ~all (softfail) — spoofed emails reach inbox with warning
  3. DKIM not detected — authenticity cannot be cryptographically verified

RECOMMENDED RECORDS
  [Copy-paste-ready DNS records with staged rollout plan]
```

---

## REST API

Start the server then browse interactive docs at `http://localhost:8000/docs`.

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/health` | Health check |
| `POST` | `/api/v1/analyze` | Synchronous single-domain analysis |
| `POST` | `/api/v1/analyze/async` | Async analysis (returns `request_id`) |
| `POST` | `/api/v1/analyze/batch` | Async batch analysis |
| `GET` | `/api/v1/status/{request_id}` | Poll async job |
| `GET` | `/api/v1/batch/{batch_id}/status` | Poll batch job |

---

## n8n Automation

Five importable workflows live in `n8n/`:

| Workflow | Trigger | Purpose |
|----------|---------|---------|
| `workflow-1-scheduled-scan.json` | Weekly cron | Scan all domains, alert on HIGH risk |
| `workflow-2-report-ingestion.json` | IMAP poll (6h) | Parse incoming aggregate reports |
| `workflow-3-on-demand-analysis.json` | Webhook POST | Single-domain analysis on demand |
| `workflow-4-alerts.json` | Webhook POST | Email + Slack alert delivery |
| `workflow-5-batch-analysis.json` | Webhook POST | Multi-domain batch scan |

See [`n8n/README.md`](n8n/README.md) for setup instructions.

---

## Setup and Client Onboarding

See [`SETUP.md`](SETUP.md) for the full step-by-step guide covering:
- Pre-engagement checklist
- Initial analysis workflow
- 6-phase DMARC deployment (monitoring → quarantine → reject)
- n8n automation setup
- Ongoing maintenance

---

## Running Tests

```bash
cd src
python3 -m pytest tests/ -q
```

215 tests, all passing.

---

## Project Structure

```
dmarc-agent/
├── src/
│   ├── dmarc_agent/          # Core Python package
│   │   ├── cli.py            # Click CLI entrypoint
│   │   ├── api_server.py     # FastAPI REST server
│   │   ├── spf_validator.py  # SPF parsing and validation
│   │   ├── dmarc_analyzer.py # DMARC record analysis
│   │   ├── dkim_checker.py   # DKIM selector verification
│   │   ├── dns_fetcher.py    # DNS queries with TTL caching
│   │   ├── risk_classifier.py# HIGH/MEDIUM/LOW risk logic
│   │   ├── record_generator.py # Staged remediation records
│   │   ├── report_parser.py  # Aggregate XML report parsing
│   │   ├── report_text.py    # Rich terminal renderer
│   │   ├── report_json.py    # JSON serializer
│   │   ├── report_html.py    # HTML report (Jinja2)
│   │   ├── models.py         # Data models
│   │   └── exceptions.py     # Error hierarchy
│   ├── tests/                # 215 unit tests
│   └── pyproject.toml
├── n8n/                      # n8n workflow JSON files + README
├── workflows/                # Additional workflow exports
├── config/
│   └── domains.json          # Domain list for scheduled scans
├── SETUP.md                  # Full client onboarding guide
└── CLAUDE.md                 # Agent operational spec
```

---

## Dependencies

| Package | Purpose |
|---------|---------|
| `click` | CLI framework |
| `dnspython` | DNS queries |
| `rich` | Terminal formatting |
| `jinja2` | HTML report templates |
| `fastapi` + `uvicorn` | REST API server (optional, `pip install -e "src/[api]"`) |
| `pydantic` | API request/response models |

Python 3.10+ required.
