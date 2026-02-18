# DMARC Security Agent — Setup & Client Onboarding

---

## Part 1: Client Onboarding Checklist

Work through this top-to-bottom for each new client domain. Each phase builds on the previous one — do not skip ahead.

---

### Phase 0 — Pre-Engagement

- [ ] Confirm you have the client's domain name(s)
- [ ] Confirm client has access to their DNS provider control panel (Cloudflare, GoDaddy, Route 53, etc.)
- [ ] Confirm client knows their email provider (Google Workspace, Microsoft 365, Mailchimp, etc.)
- [ ] Get a contact email address for DMARC reports (e.g. `dmarc@clientdomain.com` or create one)
- [ ] Ask if they use any third-party senders (Mailchimp, SendGrid, HubSpot, Zendesk, etc.)
- [ ] Install `dmarc-agent` on your analysis machine (see Installation below)

---

### Phase 1 — Initial Analysis

- [ ] Run full analysis:
  ```bash
  dmarc-agent analyze <client-domain> --format text
  ```
- [ ] Note the **risk level** (HIGH / MEDIUM / LOW)
- [ ] Save a JSON copy for your records:
  ```bash
  dmarc-agent analyze <client-domain> --format json --output reports/<client>-initial.json
  ```
- [ ] Generate an HTML report to share with the client:
  ```bash
  dmarc-agent analyze <client-domain> --format html --output reports/<client>-initial.html
  ```
- [ ] Review each issue found — note which are Critical vs Medium vs Low priority
- [ ] If client uses DKIM, check the selector:
  ```bash
  dmarc-agent verify-dkim <selector> <client-domain>
  # Common selectors to try: google, selector1, selector2, mail, default, smtp
  ```

---

### Phase 2 — Deploy DMARC Stage 1 (Monitoring)

> **Goal:** Start collecting data. Zero email disruption.

- [ ] Share the HTML report with the client and explain risks in plain English
- [ ] Get client to log in to their DNS provider
- [ ] Add the Stage 1 DMARC record from the report output:
  ```
  Type: TXT
  Name: _dmarc
  Value: v=DMARC1; p=none; rua=mailto:dmarc@<domain>; ruf=mailto:dmarc@<domain>; fo=1
  TTL: 3600
  ```
- [ ] Verify the record is live (allow 15–60 min propagation):
  ```bash
  dmarc-agent check-dmarc <client-domain>
  ```
- [ ] Confirm DMARC aggregate reports start arriving at `dmarc@<domain>` within 24–48 hours
- [ ] If using the automation stack, add domain to `workflows/config/domains.json`

---

### Phase 3 — Harden SPF (Week 2)

> **Goal:** Change softfail (~all) to hard fail (-all) once all senders are known.

- [ ] Review 1–2 weeks of DMARC aggregate reports (use `dmarc-agent parse-report <file>`)
- [ ] Identify all legitimate sending sources from the reports
- [ ] Cross-check against the client's known email services (Step 0 list)
- [ ] Update the SPF record from the agent's recommendation:
  ```
  Type: TXT
  Name: @  (or blank)
  Value: v=spf1 [mechanisms for all known senders] -all
  ```
- [ ] Send a test email from every known service (CRM, newsletter, support, etc.)
- [ ] Verify no legitimate mail bounced in the 48 hours after change
- [ ] Re-run analysis to confirm SPF status improved:
  ```bash
  dmarc-agent check-spf <client-domain>
  ```

---

### Phase 4 — Set Up DKIM (Week 2–3)

> **Goal:** Cryptographic email signing. Required for DMARC to reach LOW risk.

- [ ] Contact the client's email provider to enable DKIM signing
  - Google Workspace: Admin Console → Apps → Gmail → Authenticate email
  - Microsoft 365: Admin Center → Settings → Domains → DNS records
  - Other providers: consult their documentation
- [ ] Provider will give you a TXT record — add it to DNS:
  ```
  Type: TXT
  Name: <selector>._domainkey.<domain>
  Value: v=DKIM1; k=rsa; p=<public-key>
  ```
- [ ] Verify the DKIM record is live:
  ```bash
  dmarc-agent verify-dkim <selector> <client-domain>
  ```
- [ ] Send a test email and confirm DKIM pass in headers or DMARC report
- [ ] Re-run full analysis to confirm risk level improvement:
  ```bash
  dmarc-agent analyze <client-domain>
  ```

---

### Phase 5 — DMARC Enforcement (Week 4–6)

> **Goal:** Move from monitoring to actively blocking spoofed email.

- [ ] Confirm at least 2 weeks of DMARC reports show >95% pass rate
- [ ] Confirm all legitimate senders pass SPF or DKIM (check aggregate reports)
- [ ] Update DMARC to Stage 2 (partial quarantine):
  ```
  v=DMARC1; p=quarantine; pct=10; rua=mailto:dmarc@<domain>; ruf=mailto:dmarc@<domain>; fo=1
  ```
- [ ] Wait 1–2 weeks, monitor for any legitimate mail going to spam
- [ ] Update to Stage 3 (full quarantine):
  ```
  v=DMARC1; p=quarantine; rua=mailto:dmarc@<domain>; ruf=mailto:dmarc@<domain>; fo=1
  ```
- [ ] Wait 4–8 weeks, confirm no issues
- [ ] Update to Stage 4 (full reject — maximum protection):
  ```
  v=DMARC1; p=reject; rua=mailto:dmarc@<domain>; ruf=mailto:dmarc@<domain>; fo=1
  ```
- [ ] Run final analysis and confirm LOW risk:
  ```bash
  dmarc-agent analyze <client-domain> --format html --output reports/<client>-final.html
  ```
- [ ] Deliver final HTML report to client

---

### Phase 6 — Ongoing Monitoring (Maintenance)

- [ ] Set up scheduled scans (see n8n workflow 01, or run manually weekly)
- [ ] Process incoming DMARC aggregate reports monthly (or automate with workflow 02)
- [ ] Re-run full analysis any time the client adds a new email service
- [ ] Update SPF record when client adds new senders
- [ ] Rotate DKIM keys annually (coordinate with email provider)
- [ ] Check for DMARC policy regression every 90 days:
  ```bash
  dmarc-agent analyze <client-domain>
  ```

---

## Installation

```bash
# Clone the repo
git clone https://github.com/sinCodes11/dmarc-agent.git
cd dmarc-agent

# Install the CLI (editable mode)
pip install -e "src/[api]"

# Verify installation
dmarc-agent --version

# Run tests
cd src && python3 -m pytest tests/ -q
```

**Dependencies installed automatically:** `click`, `dnspython`, `rich`, `jinja2`, `fastapi`, `uvicorn`, `pydantic`

---

## CLI Quick Reference

```bash
# Full analysis (text output to terminal)
dmarc-agent analyze example.com

# Full analysis with a known DKIM selector
dmarc-agent analyze example.com --dkim-selector google

# Save HTML report
dmarc-agent analyze example.com --format html --output report.html

# Save JSON for scripting
dmarc-agent analyze example.com --format json --output result.json

# Quick SPF-only check
dmarc-agent check-spf example.com

# Quick DMARC-only check
dmarc-agent check-dmarc example.com

# Verify a specific DKIM selector
dmarc-agent verify-dkim selector1 example.com

# Parse an aggregate report file (.xml, .xml.gz, or .zip)
dmarc-agent parse-report report.xml.gz
dmarc-agent parse-report report.xml.gz --format json

# Start the REST API server (for n8n automation)
DMARC_API_KEY=your-secret-key dmarc-agent serve --port 8000
```

---

## Part 2: n8n Automation Setup

The `workflows/` directory contains 5 importable n8n workflow JSON files. Set up workflow 04 first — all others call it as a sub-workflow.

---

### Step 1 — Prerequisites

- [ ] n8n instance running (self-hosted or n8n Cloud)
- [ ] `dmarc-agent serve` running and reachable from the n8n host
- [ ] SMTP credentials for outgoing email alerts
- [ ] Slack webhook or bot token (if using Slack notifications)
- [ ] IMAP credentials for the DMARC report mailbox (workflow 02 only)

---

### Step 2 — Set Environment Variables in n8n

In n8n: **Settings → Environment Variables** (or set in your `.env` / `docker-compose.yml`)

| Variable | Value | Used By |
|---|---|---|
| `DMARC_API_URL` | `http://your-server:8000` | All workflows |
| `DMARC_API_KEY` | Your secret key (≥32 chars) | All workflows |
| `ALERT_WORKFLOW_ID` | Set after importing workflow 04 | 01, 02, 05 |
| `SMTP_FROM_EMAIL` | `alerts@yourdomain.com` | 01, 04 |
| `SUMMARY_EMAIL_TO` | `you@yourdomain.com` | 01 |
| `SLACK_CHANNEL_ID` | `C01234ABCDE` | 01, 04 |
| `DMARC_REPORT_BASE_URL` | `https://your-dashboard.com` | 04 |
| `REPORT_STORAGE_PATH` | `/data/dmarc-reports` | 02 |
| `IMAP_MAILBOX` | `INBOX` | 02 |
| `BATCH_DELAY_MS` | `2000` | 05 |

---

### Step 3 — Configure Credentials in n8n

In n8n: **Credentials → New**

- [ ] **SMTP Account** — for sending alert and summary emails
- [ ] **Slack Account** — Bot Token or OAuth (needs `chat:write` scope)
- [ ] **IMAP Account** — for the DMARC report mailbox (workflow 02 only)

---

### Step 4 — Import Workflow 04 First

> Workflow 04 is the alert sub-workflow. Its ID is needed before activating the others.

- [ ] In n8n: **Workflows → Import from File**
- [ ] Select `workflows/04-alert-notification.json`
- [ ] Open the imported workflow — note the workflow ID from the URL:
  `https://your-n8n.com/workflow/`**`12345`** ← this is the ID
- [ ] Set `ALERT_WORKFLOW_ID=12345` in your environment variables
- [ ] Assign the **SMTP** and **Slack** credentials to the Send nodes
- [ ] Click **Activate**

---

### Step 5 — Import Remaining Workflows

Import in this order (each can be done independently after 04 is active):

- [ ] `01-scheduled-domain-scan.json`
  - Open the **Load Domain List** Code node
  - Edit the domain list to include your client domains
  - Assign **SMTP** credential to Send Email node
  - Assign **Slack** credential to Slack node
  - Set the cron schedule if you want something other than Sunday 2AM UTC
  - Click **Activate**

- [ ] `02-dmarc-report-ingestion.json`
  - Assign **IMAP** credential to the IMAP trigger node
  - Verify `REPORT_STORAGE_PATH` directory exists and n8n has write access
  - Click **Activate** (will start polling immediately)

- [ ] `03-on-demand-analysis.json`
  - Note the webhook URL shown on the Webhook node (click the node to see it)
  - This is your `POST /dmarc/analyze` endpoint — use it from external systems
  - Click **Activate**

- [ ] `05-batch-analysis.json`
  - Note the webhook URL for `POST /dmarc/batch`
  - Click **Activate**

---

### Step 6 — Test Each Workflow

- [ ] **Workflow 01** — Click **Execute Workflow** manually. Confirm domains are analyzed and you receive an email and Slack message.
- [ ] **Workflow 02** — Forward a DMARC aggregate report email to the configured mailbox. Confirm it gets parsed within 6 hours (or trigger manually).
- [ ] **Workflow 03** — Send a test request:
  ```bash
  curl -X POST https://your-n8n.com/webhook/dmarc/analyze \
    -H "Authorization: Bearer your-api-key" \
    -H "Content-Type: application/json" \
    -d '{"domain": "example.com"}'
  ```
- [ ] **Workflow 04** — Triggered automatically by others. To test manually, run workflow 01 against a HIGH risk domain.
- [ ] **Workflow 05** — Send a test batch request:
  ```bash
  curl -X POST https://your-n8n.com/webhook/dmarc/batch \
    -H "Authorization: Bearer your-api-key" \
    -H "Content-Type: application/json" \
    -d '{"domains": ["example.com", "example.org"]}'
  ```

---

### Step 7 — Ongoing Maintenance

- [ ] Add new client domains to the **Load Domain List** node in workflow 01
- [ ] Review n8n execution logs weekly for errors
- [ ] Rotate `DMARC_API_KEY` every 90 days (update in both n8n env vars and the API server)
- [ ] Keep `dmarc-agent` updated by pulling the latest from the repo and re-installing
