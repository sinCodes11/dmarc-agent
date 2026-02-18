# n8n Workflow Integration

Five n8n workflows that automate the DMARC Security Agent for scheduled scanning, report ingestion, on-demand analysis, alerting, and batch processing.

## Prerequisites

1. **DMARC API server running** — start with:
   ```bash
   pip install 'dmarc-agent[api]'
   DMARC_API_KEY=your-key dmarc-agent serve --port 8000
   ```

2. **n8n instance** — self-hosted or cloud. Set these environment variables in n8n:
   ```
   DMARC_API_BASE_URL=http://your-server:8000
   DMARC_API_KEY=your-key           # must match the server key
   SLACK_WEBHOOK_URL=https://hooks.slack.com/...
   SMTP_FROM=dmarc-alerts@example.com
   ALERT_EMAIL=security-team@example.com
   DOMAINS_CONFIG_PATH=/path/to/config/domains.json
   ```

3. **n8n credentials** (configure under Settings → Credentials):
   - **DMARC IMAP Account** — for Workflow 2 (report ingestion)
   - **DMARC SMTP Account** — for Workflow 4 (email alerts)

---

## Importing Workflows

1. Open n8n → **Workflows** → **Import from file**
2. Select any `.json` file from this directory
3. Configure environment variables and credentials
4. **Activate** the workflow when ready

---

## Workflows

### Workflow 1 — Scheduled Domain Scan (`workflow-1-scheduled-scan.json`)
- **Trigger:** Weekly, Sunday 02:00 UTC (configurable in Schedule Trigger node)
- **What it does:** Reads `domains.json`, analyses each domain via the API, sends a Slack alert for any HIGH risk result
- **Customise:** Change schedule frequency in the Schedule Trigger node

### Workflow 2 — DMARC Report Ingestion (`workflow-2-report-ingestion.json`)
- **Trigger:** IMAP polling every 6 hours
- **What it does:** Watches a mailbox for DMARC aggregate reports, extracts XML/gz/zip attachments, re-analyzes the domain, alerts on anomalies
- **Requires:** IMAP credentials configured in n8n

### Workflow 3 — On-Demand Analysis (`workflow-3-on-demand-analysis.json`)
- **Trigger:** Webhook `POST /webhook/dmarc-analyze`
- **What it does:** Accepts a domain, runs a full analysis, returns JSON synchronously
- **Use from curl:**
  ```bash
  curl -X POST https://your-n8n/webhook/dmarc-analyze \
    -H 'Content-Type: application/json' \
    -d '{"domain":"example.com","options":{"dkim_selector":"google"}}'
  ```

### Workflow 4 — Alert and Notification (`workflow-4-alerts.json`)
- **Trigger:** Webhook `POST /webhook/dmarc-alert`
- **What it does:** Receives alert events from other workflows, routes by severity (critical → Slack + email, warning → Slack only)
- **Alert payload:**
  ```json
  {
    "alert_type": "risk_level_change",
    "domain": "example.com",
    "risk_level": "HIGH",
    "previous_risk_level": "MEDIUM",
    "details": ["SPF hardened to -all"]
  }
  ```
- **Alert types:** `risk_level_change`, `anomaly_detected`, `configuration_change`, `report_processing_failure`, `scan_failure`

### Workflow 5 — Batch Analysis (`workflow-5-batch-analysis.json`)
- **Trigger:** Webhook `POST /webhook/dmarc-batch`
- **What it does:** Accepts up to 100 domains, submits a batch job to the API, polls until complete, sends a Slack summary
- **Use from curl:**
  ```bash
  curl -X POST https://your-n8n/webhook/dmarc-batch \
    -H 'Content-Type: application/json' \
    -d '{"domains":["example1.com","example2.com","example3.com"]}'
  ```

---

## API Endpoints (called by n8n)

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/health` | Health check (no auth) |
| `POST` | `/api/v1/analyze` | Synchronous single-domain analysis |
| `POST` | `/api/v1/analyze/async` | Async single-domain (returns `request_id`) |
| `POST` | `/api/v1/analyze/batch` | Async batch (returns `batch_id`) |
| `GET` | `/api/v1/status/{request_id}` | Poll async job status |
| `GET` | `/api/v1/batch/{batch_id}/status` | Poll batch status |

Interactive API docs: `http://your-server:8000/docs`

---

## Rate Limits (per API key, per 60-second window)

| Endpoint | Limit |
|----------|-------|
| `/analyze` | 10 req/min |
| `/analyze/batch` | 5 req/min |
| `/status` | 60 req/min |

---

## Connecting Workflows Together

Call Workflow 4 (alerts) from Workflows 1 or 2 by adding an HTTP Request node:
```
POST https://your-n8n/webhook/dmarc-alert
{
  "alert_type": "risk_level_change",
  "domain": "{{ $json.domain }}",
  "risk_level": "{{ $json.risk_level }}"
}
```
