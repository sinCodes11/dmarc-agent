# Purpose and Scope

Defines automation integration specifications, workflow orchestration patterns, scheduling logic, and external system connectivity for the DMARC Security Agent. Governs n8n workflow design, API endpoint definitions, webhook handling, notification routing, and batch processing protocols.

# Execution Context

- Agent operates as automation orchestrator and integration layer
- Applies to: Scheduled scans, report processing pipelines, alert workflows, API integrations
- Input: Trigger events (schedule, webhook, manual), domain lists, report files
- Output: Analysis results, notifications, reports, API responses
- Platforms: n8n, Make (Integromat), Zapier, custom webhook consumers, cron-based scheduling
- Integration: Orchestrates all DMARC system components (CLAUDE.md, dmarc-parser.md, spf-validator.md, report-generator.md, dns-fetcher.md)

# Authoritative Sources of Truth

1. CLAUDE.md automation integration section
2. n8n workflow documentation
3. Webhook security standards (HMAC signing, TLS)
4. Email delivery standards for notifications
5. API design best practices (REST, JSON)

# Planning and Execution Rules

## Workflow Design Principles

- Idempotent operations (safe to retry)
- Atomic steps with clear success/failure states
- Graceful degradation on component failure
- Comprehensive logging at each step
- Rate limiting for DNS queries and API calls
- Secrets managed via environment variables (never hardcoded)

## Execution Order

**For each workflow invocation:**
1. Validate trigger event and payload
2. Authenticate request (if external trigger)
3. Extract domain(s) and parameters
4. Execute analysis pipeline
5. Generate output (report, notification, API response)
6. Deliver results to configured destinations
7. Log execution metadata
8. Handle errors and retries

# Workflow Definitions

## Workflow 1: Scheduled Domain Scan

**Purpose:** Periodic security analysis of configured domains
**Trigger:** Cron schedule (configurable)
**Default schedule:** Weekly (Sunday 02:00 UTC)

**n8n workflow structure:**
```
[Cron Trigger]
    → [Read Domain List]
    → [For Each Domain]
        → [dns-fetcher: Query DNS Records]
        → [spf-validator: Validate SPF]
        → [CLAUDE.md: Full Analysis]
        → [report-generator: Generate Report]
        → [Store Results]
        → [Check for Changes Since Last Scan]
    → [Aggregate Results]
    → [Send Summary Notification]
    → [Archive Reports]
```

**Configuration:**
```json
{
  "workflow_id": "scheduled-domain-scan",
  "schedule": {
    "cron": "0 2 * * 0",
    "timezone": "UTC",
    "enabled": true
  },
  "domains": {
    "source": "config_file|database|api",
    "path": "/config/domains.json"
  },
  "notifications": {
    "always_notify": false,
    "notify_on_change": true,
    "notify_on_high_risk": true,
    "channels": ["email", "slack"]
  },
  "rate_limit": {
    "dns_queries_per_second": 5,
    "domains_parallel": 3,
    "delay_between_domains_ms": 2000
  }
}
```

**Domain list format:**
```json
{
  "domains": [
    {
      "domain": "example.com",
      "owner": "Client A",
      "contact_email": "admin@example.com",
      "priority": "high",
      "last_scan": "ISO-8601",
      "last_risk_level": "MEDIUM"
    }
  ]
}
```

## Workflow 2: DMARC Report Ingestion

**Purpose:** Process incoming DMARC aggregate reports
**Trigger:** Email receipt (IMAP polling) or webhook
**Processing frequency:** Every 6 hours or on receipt

**n8n workflow structure:**
```
[IMAP Trigger / Webhook]
    → [Extract Attachment]
    → [Decompress (gzip/zip)]
    → [Validate XML Schema]
    → [dmarc-parser: Parse Report]
    → [Store Normalized Data]
    → [Check Anomaly Thresholds]
    → [Branch: Anomaly Detected?]
        → [Yes: Trigger Alert Workflow]
        → [No: Continue]
    → [Update Domain Statistics]
    → [Log Processing Result]
```

**Email ingestion configuration:**
```json
{
  "workflow_id": "dmarc-report-ingestion",
  "imap": {
    "host": "imap.example.com",
    "port": 993,
    "tls": true,
    "mailbox": "INBOX",
    "search_criteria": "UNSEEN SUBJECT \"Report domain:\"",
    "poll_interval_minutes": 360,
    "mark_as_read": true,
    "move_to_folder": "Processed"
  },
  "processing": {
    "max_attachment_size_mb": 50,
    "accepted_formats": ["application/gzip", "application/zip", "application/xml"],
    "reject_invalid_schema": true,
    "store_raw": true
  },
  "anomaly_thresholds": {
    "volume_spike_multiplier": 2.0,
    "pass_rate_drop_percent": 10,
    "new_unauthorized_source": true,
    "trigger_alert_on_any": true
  }
}
```

## Workflow 3: On-Demand Analysis (API)

**Purpose:** Single-domain analysis via API request
**Trigger:** HTTP POST to analysis endpoint
**Response:** Synchronous (with timeout) or async with callback

**n8n workflow structure:**
```
[Webhook Trigger]
    → [Validate Request]
    → [Authenticate (API Key)]
    → [Extract Domain]
    → [dns-fetcher: Query All Records]
    → [spf-validator: Validate SPF]
    → [CLAUDE.md: Full Analysis]
    → [report-generator: Generate Report]
    → [Return Response]
```

**API endpoint specification:**
```
POST /api/v1/analyze
Content-Type: application/json
Authorization: Bearer <api-key>

Request Body:
{
  "domain": "example.com",
  "options": {
    "include_dmarc_reports": false,
    "report_format": "json|html|pdf",
    "callback_url": "https://... (optional for async)"
  }
}

Response (synchronous):
{
  "request_id": "uuid",
  "domain": "example.com",
  "timestamp": "ISO-8601",
  "risk_level": "HIGH|MEDIUM|LOW",
  "analysis": { ... full CLAUDE.md output as JSON ... },
  "report_url": "https://... (if HTML/PDF requested)"
}

Response (async):
{
  "request_id": "uuid",
  "status": "processing",
  "estimated_completion": "ISO-8601",
  "callback_url": "https://...",
  "status_url": "/api/v1/status/<request_id>"
}
```

## Workflow 4: Alert and Notification

**Purpose:** Deliver alerts for risk changes, anomalies, or threshold breaches
**Trigger:** Internal event from other workflows
**Channels:** Email, Slack, webhook, SMS (configurable)

**n8n workflow structure:**
```
[Internal Trigger (event)]
    → [Determine Alert Severity]
    → [Select Notification Channels]
    → [Format Message per Channel]
    → [For Each Channel]
        → [Send Notification]
        → [Log Delivery Status]
    → [Update Alert History]
```

**Alert types:**
```json
{
  "alert_types": {
    "risk_level_change": {
      "description": "Domain risk level changed since last scan",
      "severity_mapping": {
        "LOW_to_MEDIUM": "warning",
        "LOW_to_HIGH": "critical",
        "MEDIUM_to_HIGH": "critical",
        "HIGH_to_MEDIUM": "info",
        "HIGH_to_LOW": "info",
        "MEDIUM_to_LOW": "info"
      }
    },
    "anomaly_detected": {
      "description": "DMARC report shows unusual activity",
      "severity": "warning",
      "sub_types": ["volume_spike", "new_unauthorized_source", "pass_rate_drop"]
    },
    "configuration_change": {
      "description": "DNS records changed since last scan",
      "severity": "info"
    },
    "report_processing_failure": {
      "description": "Failed to process DMARC aggregate report",
      "severity": "warning"
    },
    "scan_failure": {
      "description": "Scheduled scan failed for domain",
      "severity": "warning"
    }
  }
}
```

**Notification templates:**

**Email template:**
```
Subject: [DMARC Alert] [severity] - [domain] - [alert_type]

[domain] Email Security Alert
Severity: [Critical/Warning/Info]
Time: [timestamp]

[alert_description]

Current Risk Level: [risk_level]
Previous Risk Level: [previous_risk_level]

Key Details:
- [detail 1]
- [detail 2]
- [detail 3]

Recommended Action:
[action_description]

View Full Report: [report_url]

---
DMARC Security Agent | Automated Alert
```

**Slack template:**
```json
{
  "blocks": [
    {
      "type": "header",
      "text": { "type": "plain_text", "text": "DMARC Alert: [domain]" }
    },
    {
      "type": "section",
      "fields": [
        { "type": "mrkdwn", "text": "*Severity:*\n[severity]" },
        { "type": "mrkdwn", "text": "*Risk Level:*\n[risk_level]" },
        { "type": "mrkdwn", "text": "*Domain:*\n[domain]" },
        { "type": "mrkdwn", "text": "*Time:*\n[timestamp]" }
      ]
    },
    {
      "type": "section",
      "text": { "type": "mrkdwn", "text": "[alert_description]" }
    },
    {
      "type": "actions",
      "elements": [
        {
          "type": "button",
          "text": { "type": "plain_text", "text": "View Report" },
          "url": "[report_url]"
        }
      ]
    }
  ]
}
```

## Workflow 5: Batch Analysis

**Purpose:** Analyze multiple domains in a single run
**Trigger:** API request with domain list, or CSV upload
**Use case:** MSP onboarding, portfolio assessment

**n8n workflow structure:**
```
[Webhook / File Upload Trigger]
    → [Parse Domain List]
    → [Validate Domains]
    → [Create Batch Job Record]
    → [For Each Domain (rate-limited)]
        → [Execute Workflow 3: On-Demand Analysis]
        → [Store Individual Result]
        → [Update Progress]
    → [Aggregate Batch Results]
    → [report-generator: Generate Batch Report]
    → [Notify Requester]
    → [Return Batch Results]
```

**Batch API endpoint:**
```
POST /api/v1/analyze/batch
Content-Type: application/json
Authorization: Bearer <api-key>

Request Body:
{
  "domains": ["example1.com", "example2.com", "example3.com"],
  "options": {
    "report_format": "json",
    "callback_url": "https://...",
    "priority": "normal|high"
  }
}

Response:
{
  "batch_id": "uuid",
  "status": "processing",
  "total_domains": 3,
  "estimated_completion": "ISO-8601",
  "status_url": "/api/v1/batch/<batch_id>/status"
}
```

**Batch status endpoint:**
```
GET /api/v1/batch/<batch_id>/status

Response:
{
  "batch_id": "uuid",
  "status": "processing|completed|partial_failure",
  "progress": {
    "total": 3,
    "completed": 2,
    "failed": 0,
    "pending": 1
  },
  "results": [
    {
      "domain": "example1.com",
      "status": "completed",
      "risk_level": "HIGH",
      "report_url": "..."
    }
  ]
}
```

# API Specification

## Authentication

**API key authentication:**
```
Authorization: Bearer <api-key>
```

**Key management:**
- Keys stored as environment variables or in secrets manager
- Keys must be >= 32 characters
- Keys rotated every 90 days
- Rate limits enforced per key
- Keys scoped to specific endpoints (optional)

**Webhook signature verification (inbound):**
```
X-Webhook-Signature: sha256=<HMAC-SHA256(payload, secret)>
```

**Verification logic:**
```
function verifyWebhook(payload, signature, secret):
    expected = HMAC-SHA256(payload, secret)
    return constant_time_compare(signature, "sha256=" + expected)
```

## Rate Limiting

**Default limits:**
```json
{
  "rate_limits": {
    "analyze": {
      "per_minute": 10,
      "per_hour": 100,
      "per_day": 500
    },
    "batch": {
      "per_hour": 5,
      "max_domains_per_batch": 100
    },
    "status": {
      "per_minute": 60
    }
  }
}
```

**Rate limit headers:**
```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1234567890
```

## Error Responses

**Standard error format:**
```json
{
  "error": {
    "code": "RATE_LIMIT_EXCEEDED|INVALID_DOMAIN|AUTH_FAILED|INTERNAL_ERROR|DNS_TIMEOUT",
    "message": "Human-readable error description",
    "request_id": "uuid",
    "timestamp": "ISO-8601",
    "retry_after": 60
  }
}
```

**HTTP status codes:**
| Code | Usage |
|------|-------|
| 200 | Successful analysis |
| 202 | Async request accepted |
| 400 | Invalid request (bad domain, missing fields) |
| 401 | Authentication failed |
| 429 | Rate limit exceeded |
| 500 | Internal processing error |
| 503 | Service temporarily unavailable (DNS issues) |

# Data Storage

## Storage Requirements

**Analysis results:**
```json
{
  "storage": {
    "analysis_results": {
      "retention_days": 365,
      "format": "JSON",
      "indexed_fields": ["domain", "timestamp", "risk_level"]
    },
    "dmarc_reports": {
      "retention_days": 180,
      "format": "JSON (normalized)",
      "raw_retention_days": 30
    },
    "alerts": {
      "retention_days": 90,
      "format": "JSON"
    },
    "batch_jobs": {
      "retention_days": 30,
      "format": "JSON"
    }
  }
}
```

**Storage backends (configurable):**
- File system (JSON files, for simple deployments)
- SQLite (single-server deployments)
- PostgreSQL (production multi-user)
- S3-compatible object storage (reports and raw data)

## Data Schema

**Domain analysis record:**
```json
{
  "id": "uuid",
  "domain": "example.com",
  "analyzed_at": "ISO-8601",
  "risk_level": "HIGH|MEDIUM|LOW",
  "spf_status": {},
  "dkim_status": {},
  "dmarc_status": {},
  "findings": [],
  "recommended_records": {},
  "previous_analysis_id": "uuid (nullable)",
  "changes_from_previous": []
}
```

# Scheduling and Orchestration

## Schedule Configuration

**Cron expressions for common schedules:**
```
Daily at 2 AM UTC:     0 2 * * *
Weekly Sunday 2 AM:    0 2 * * 0
Bi-weekly Monday 6 AM: 0 6 1,15 * *
Monthly 1st at 3 AM:   0 3 1 * *
Every 6 hours:         0 */6 * * *
```

**Schedule management:**
- Schedules configurable per domain or domain group
- Priority domains can have more frequent scans
- Rate limiting prevents overloading DNS resolvers
- Missed schedules execute at next opportunity (no skip/pile-up)
- Maintenance windows respect configured blackout periods

## Retry Logic

**Retry configuration:**
```json
{
  "retry": {
    "max_attempts": 3,
    "backoff_strategy": "exponential",
    "initial_delay_ms": 5000,
    "max_delay_ms": 300000,
    "retry_on": [
      "DNS_TIMEOUT",
      "NETWORK_ERROR",
      "RATE_LIMIT"
    ],
    "do_not_retry_on": [
      "INVALID_DOMAIN",
      "AUTH_FAILED",
      "INVALID_INPUT"
    ]
  }
}
```

**Exponential backoff formula:**
```
delay = min(initial_delay * 2^(attempt - 1), max_delay) + random_jitter(0, 1000ms)
```

# Security Requirements

## Secrets Management

**Required secrets:**
```
DMARC_API_KEY          - API authentication key
SMTP_PASSWORD          - Email notification credentials
SLACK_WEBHOOK_URL      - Slack notification URL
WEBHOOK_SIGNING_SECRET - Inbound webhook verification
DATABASE_URL           - Storage backend connection (if applicable)
```

**Rules:**
- All secrets via environment variables or secrets manager
- Never logged, never in configuration files
- Rotated per organizational policy (minimum 90 days)
- Scoped to minimum required permissions

## Network Security

- All external communications over TLS 1.2+
- Webhook endpoints verify signatures before processing
- DNS queries use trusted resolvers
- API endpoints enforce authentication on all routes
- Input validation on all external data

# Integration Points

## CLAUDE.md Integration

- Receives analysis requests from API and scheduled workflows
- Returns structured analysis per CLAUDE.md automation output format
- Risk classification feeds into alert logic

## dns-fetcher.md Integration

- All DNS queries routed through dns-fetcher for caching and rate limiting
- Bulk queries for batch analysis optimized for throughput
- TTL-aware caching reduces redundant queries

## dmarc-parser.md Integration

- Report ingestion workflow passes raw XML to parser
- Parser returns normalized data for storage and alerting
- Anomaly thresholds checked against parser output

## report-generator.md Integration

- Analysis results passed to generator for formatted output
- Batch reports aggregate multiple domain analyses
- Report format configurable per workflow

## spf-validator.md Integration

- SPF validation integrated into analysis pipeline
- Lookup counting results feed into risk assessment
- Validation issues feed into findings

# Constraints and Prohibitions

## Critical Prohibitions

**Never:**
- Store API keys or secrets in workflow definitions
- Send notifications without rate limiting
- Process DMARC reports without schema validation
- Execute batch operations without rate limiting DNS queries
- Skip authentication on API endpoints
- Log sensitive data (credentials, PII, full email content)
- Retry indefinitely on persistent failures
- Process domains not in authorized list (if access control enabled)

**Always:**
- Authenticate all external requests
- Validate all input before processing
- Rate limit DNS queries per dns-fetcher.md policy
- Log workflow execution with request IDs
- Handle errors gracefully with appropriate HTTP status codes
- Include request ID in all responses and logs
- Verify webhook signatures on inbound requests
- Respect TTL and caching for DNS data

# Verification Criteria

## Workflow Complete When

**Per-invocation:**
- [ ] Trigger event validated
- [ ] Authentication verified (if external)
- [ ] Input validated and sanitized
- [ ] Analysis pipeline completed (or error handled)
- [ ] Results stored successfully
- [ ] Notifications delivered (if applicable)
- [ ] Response returned to caller
- [ ] Execution logged with metadata

**System-level:**
- [ ] All scheduled workflows executing on time
- [ ] API endpoints responding within SLA (< 30s for sync, < 5min for async)
- [ ] Error rate < 5% over 24-hour window
- [ ] No unprocessed DMARC reports older than 24 hours
- [ ] Alert delivery rate > 99%
- [ ] Storage within retention limits
- [ ] Rate limits enforced and not exceeded
