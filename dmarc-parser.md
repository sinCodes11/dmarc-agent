# Purpose and Scope

Defines parsing logic, data extraction protocols, and validation rules for DMARC aggregate (RUA) and forensic (RUF) reports. Governs XML parsing, data normalization, trend analysis, and structured output generation for the DMARC Security Agent system.

# Execution Context

- Agent operates as DMARC report parser and analyzer
- Applies to: DMARC aggregate XML reports (RFC 7489 Section 7.2), forensic reports (RFC 6591)
- Input: Raw XML aggregate reports, ARF-format forensic reports
- Output: Normalized JSON data, trend summaries, authentication failure analysis
- Integration: Feeds into report-generator.md, automation-workflow.md, and CLAUDE.md risk classification

# Authoritative Sources of Truth

1. RFC 7489 - Domain-based Message Authentication, Reporting, and Conformance (DMARC)
2. RFC 7489 Appendix C - DMARC XML Schema
3. RFC 6591 - Authentication Failure Reporting Using ARF
4. Provided raw XML report data
5. CLAUDE.md risk classification framework

# Planning and Execution Rules

## Input Processing

**Accept only:**
- Valid XML conforming to DMARC aggregate report schema
- ARF-format forensic failure reports
- Gzip-compressed or zip-compressed report files
- MIME-attached reports from email

**Never accept:**
- Malformed XML without attempting repair
- Reports missing mandatory fields (report_metadata, policy_published, record)
- Reports from unverified sources without flagging
- Truncated or partial reports without warning

**Input validation sequence:**
1. Decompress if compressed (gzip/zip)
2. Validate XML well-formedness
3. Validate against DMARC schema
4. Extract report metadata
5. Parse policy published
6. Parse individual records
7. Normalize data to internal format

## Processing Sequence

**Mandatory execution order:**
1. Validate input format
2. Extract report metadata
3. Parse published policy
4. Parse authentication results per record
5. Aggregate pass/fail statistics
6. Identify authentication failure patterns
7. Classify sources (legitimate vs suspicious)
8. Generate normalized output
9. Flag anomalies and trends

**No steps may be skipped or reordered**

# Aggregate Report Parsing Protocol

## Report Structure

**Required XML elements:**

```xml
<feedback>
  <report_metadata>
    <org_name>Reporter Organization</org_name>
    <email>reporter@example.com</email>
    <report_id>unique-id</report_id>
    <date_range>
      <begin>unix-timestamp</begin>
      <end>unix-timestamp</end>
    </date_range>
  </report_metadata>
  <policy_published>
    <domain>example.com</domain>
    <adkim>r|s</adkim>
    <aspf>r|s</aspf>
    <p>none|quarantine|reject</p>
    <sp>none|quarantine|reject</sp>
    <pct>0-100</pct>
  </policy_published>
  <record>
    <row>
      <source_ip>IP address</source_ip>
      <count>message count</count>
      <policy_evaluated>
        <disposition>none|quarantine|reject</disposition>
        <dkim>pass|fail</dkim>
        <spf>pass|fail</spf>
      </policy_evaluated>
    </row>
    <identifiers>
      <header_from>domain</header_from>
    </identifiers>
    <auth_results>
      <dkim>
        <domain>signing domain</domain>
        <result>pass|fail|none|...</result>
      </dkim>
      <spf>
        <domain>envelope domain</domain>
        <result>pass|fail|softfail|none|...</result>
      </spf>
    </auth_results>
  </record>
</feedback>
```

## Metadata Extraction

**Extract and store:**
```json
{
  "reporter": {
    "org_name": "string",
    "email": "string",
    "extra_contact_info": "string (optional)"
  },
  "report_id": "string",
  "date_range": {
    "begin": "ISO-8601 datetime",
    "end": "ISO-8601 datetime",
    "duration_hours": "number"
  }
}
```

**Validation rules:**
- `org_name` must be non-empty
- `report_id` must be unique within processing window
- `date_range.begin` must be before `date_range.end`
- Duration must not exceed 7 days (flag if longer)
- Duplicate report_ids must be flagged and deduplicated

## Policy Published Extraction

**Extract and validate:**
```json
{
  "domain": "string",
  "adkim": "r|s (default: r)",
  "aspf": "r|s (default: r)",
  "policy": "none|quarantine|reject",
  "subdomain_policy": "none|quarantine|reject (default: inherits from policy)",
  "percentage": "0-100 (default: 100)"
}
```

**Validation rules:**
- `domain` must match expected analysis domain
- `policy` must be one of: none, quarantine, reject
- `percentage` must be 0-100 (flag if < 100)
- Mismatched domain triggers warning

## Record Parsing

**Per-record extraction:**
```json
{
  "source_ip": "string",
  "count": "integer",
  "policy_evaluated": {
    "disposition": "none|quarantine|reject",
    "dkim": "pass|fail",
    "spf": "pass|fail",
    "reason": [
      {
        "type": "forwarded|sampled_out|trusted_forwarder|mailing_list|local_policy|other",
        "comment": "string (optional)"
      }
    ]
  },
  "identifiers": {
    "header_from": "string",
    "envelope_from": "string (optional)",
    "envelope_to": "string (optional)"
  },
  "auth_results": {
    "dkim": [
      {
        "domain": "string",
        "selector": "string (optional)",
        "result": "pass|fail|none|policy|neutral|temperror|permerror"
      }
    ],
    "spf": [
      {
        "domain": "string",
        "scope": "mfrom|helo",
        "result": "pass|fail|softfail|neutral|none|temperror|permerror"
      }
    ]
  }
}
```

**Validation rules:**
- `source_ip` must be valid IPv4 or IPv6
- `count` must be positive integer
- `disposition` must match one of the valid values
- At least one auth_results entry required
- `header_from` must be present

# Forensic Report Parsing Protocol

## ARF Format Processing

**Extract from forensic reports:**
```json
{
  "feedback_type": "auth-failure",
  "user_agent": "string",
  "version": "string",
  "original_mail_from": "string",
  "arrival_date": "ISO-8601",
  "source_ip": "string",
  "reported_domain": "string",
  "authentication_results": "string",
  "delivery_result": "delivered|spam|reject|other",
  "auth_failure": "dmarc|dkim|spf|other",
  "original_headers": "string (sanitized)"
}
```

**Security constraints:**
- Strip message body content (privacy)
- Sanitize headers (remove sensitive routing info)
- Do not store recipient addresses
- Flag PII and redact before storage

# Data Aggregation Logic

## Statistics Generation

**Per-report statistics:**
```json
{
  "total_messages": "sum of all record counts",
  "dkim_pass": "count where dkim=pass",
  "dkim_fail": "count where dkim=fail",
  "spf_pass": "count where spf=pass",
  "spf_fail": "count where spf=fail",
  "fully_aligned": "count where both dkim=pass AND spf=pass",
  "fully_failed": "count where both dkim=fail AND spf=fail",
  "disposition_none": "count where disposition=none",
  "disposition_quarantine": "count where disposition=quarantine",
  "disposition_reject": "count where disposition=reject",
  "unique_sources": "count of distinct source_ips",
  "pass_rate_dkim": "percentage",
  "pass_rate_spf": "percentage",
  "pass_rate_overall": "percentage (either dkim OR spf pass)"
}
```

## Source Classification

**Classify each source IP:**

**Known legitimate:**
```
- IP matches SPF include mechanisms
- IP belongs to known email provider (Google, Microsoft, Amazon SES, etc.)
- Reverse DNS resolves to expected provider domain
- Historical pass rate > 95%
```

**Suspected forwarding:**
```
- SPF fails but DKIM passes
- IP belongs to known forwarding service
- Policy reason includes "forwarded" or "mailing_list"
- Consistent pattern across multiple reports
```

**Suspicious/unauthorized:**
```
- Both SPF and DKIM fail
- IP does not match any authorized sender
- No known forwarding pattern
- Low volume from unfamiliar source
- Geographic anomaly (unexpected origin)
```

**Classification output:**
```json
{
  "source_ip": "1.2.3.4",
  "classification": "legitimate|forwarding|suspicious|unknown",
  "confidence": "high|medium|low",
  "evidence": [
    "SPF pass via include:_spf.google.com",
    "DKIM pass for domain example.com"
  ],
  "reverse_dns": "mail-server.google.com (if available)",
  "message_count": 1500,
  "pass_rate": 99.8
}
```

## Trend Analysis

**Cross-report trending (when multiple reports available):**
```json
{
  "period": {
    "start": "ISO-8601",
    "end": "ISO-8601",
    "reports_analyzed": "integer"
  },
  "trends": {
    "total_volume": {
      "current": "integer",
      "previous": "integer",
      "change_percent": "number"
    },
    "pass_rate": {
      "current": "percentage",
      "previous": "percentage",
      "direction": "improving|declining|stable"
    },
    "new_sources": [
      {
        "ip": "string",
        "first_seen": "ISO-8601",
        "classification": "string",
        "volume": "integer"
      }
    ],
    "disappeared_sources": [
      {
        "ip": "string",
        "last_seen": "ISO-8601",
        "was_classified": "string"
      }
    ],
    "anomalies": [
      {
        "type": "volume_spike|new_unauthorized|pass_rate_drop|geographic_shift",
        "severity": "high|medium|low",
        "description": "string",
        "affected_records": "integer"
      }
    ]
  }
}
```

**Anomaly detection thresholds:**
- Volume spike: > 200% of 7-day average
- Pass rate drop: > 10% decrease from baseline
- New unauthorized source: any new IP with both DKIM and SPF fail
- Geographic shift: new source country not seen in prior 30 days

# Output Standards

## Normalized Report Format

**Mandatory output structure:**
```json
{
  "parse_metadata": {
    "parser_version": "1.0",
    "parsed_at": "ISO-8601",
    "input_format": "aggregate|forensic",
    "validation_status": "valid|warnings|errors",
    "validation_messages": []
  },
  "report": {
    "metadata": {},
    "policy_published": {},
    "records": [],
    "statistics": {},
    "source_classifications": [],
    "trends": {}
  },
  "risk_indicators": {
    "unauthorized_senders": "integer",
    "authentication_failures": "integer",
    "policy_overrides": "integer",
    "spoofing_attempts": "integer"
  },
  "recommendations": [
    {
      "priority": "critical|high|medium|low",
      "action": "string",
      "reason": "string",
      "affected_records": "integer"
    }
  ]
}
```

## Error Handling

**Parse errors:**
```json
{
  "error_type": "schema_violation|missing_field|invalid_value|malformed_xml",
  "field": "xpath to problematic element",
  "expected": "expected format or value",
  "actual": "what was found",
  "severity": "fatal|warning",
  "action": "skipped_record|used_default|halted_parse"
}
```

**Error severity rules:**
- Missing `report_metadata`: Fatal - halt parsing
- Missing `policy_published`: Fatal - halt parsing
- Missing individual `record` fields: Warning - use defaults, flag in output
- Invalid IP address: Warning - include raw value, flag
- Invalid timestamp: Warning - use report receipt time, flag

# Integration Points

## CLAUDE.md Integration

**Feed parsed data to risk classification:**
- Unauthorized sender count informs risk level
- Pass rate trends inform progression recommendations
- Source classification validates SPF/DKIM configuration
- Anomalies trigger re-analysis recommendations

## report-generator.md Integration

**Provide to report generator:**
- Normalized statistics for charts
- Source classification for sender tables
- Trend data for timeline visualizations
- Risk indicators for executive summary

## automation-workflow.md Integration

**Trigger conditions:**
- New report received (scheduled processing)
- Anomaly detected (immediate alert)
- Pass rate below threshold (escalation)
- New unauthorized source detected (alert)

# Constraints and Prohibitions

## Critical Prohibitions

**Never:**
- Store or output raw email message bodies
- Retain recipient email addresses from forensic reports
- Fabricate report data not present in input
- Skip validation of XML structure
- Assume report completeness without verification
- Merge reports from different domains without flagging
- Ignore schema validation errors silently

**Always:**
- Validate XML before parsing
- Deduplicate reports by report_id
- Normalize timestamps to UTC
- Flag data quality issues in output
- Classify all source IPs
- Generate statistics even for single-record reports
- Include parse metadata in all outputs

# Verification Criteria

## Parse Complete When

- [ ] All XML elements extracted
- [ ] Report metadata validated
- [ ] Policy published parsed and validated
- [ ] All records parsed with auth results
- [ ] Statistics calculated and verified
- [ ] Source IPs classified
- [ ] Anomalies detected and flagged
- [ ] Output conforms to normalized format
- [ ] Error/warning log complete
- [ ] Integration data prepared for downstream consumers
