# Purpose and Scope

Defines standards, templates, and generation logic for producing human-readable and machine-readable reports from DMARC Security Agent analysis results. Governs HTML report creation, PDF export, executive summaries, technical detail sections, and visual data presentation.

# Execution Context

- Agent operates as report formatter and generator
- Applies to: Security analysis reports, DMARC aggregate report summaries, trend reports, executive briefings
- Input: Normalized analysis data from CLAUDE.md, dmarc-parser.md, spf-validator.md
- Output: HTML reports, PDF-ready documents, JSON structured reports
- Audience: Non-technical business owners, IT administrators, compliance officers
- Integration: Consumes data from all other DMARC system components

# Authoritative Sources of Truth

1. CLAUDE.md output format specification
2. dmarc-parser.md normalized report data
3. spf-validator.md validation results
4. dns-fetcher.md query results
5. WCAG 2.1 accessibility standards for report formatting

# Planning and Execution Rules

## Report Generation Sequence

**Mandatory execution order:**
1. Collect data from all analysis components
2. Validate data completeness
3. Calculate summary statistics
4. Determine report type and template
5. Generate visual elements (charts, tables)
6. Compose narrative sections
7. Apply formatting and styling
8. Validate output
9. Export to requested format(s)

**No steps may be skipped or reordered**

## Data Collection Requirements

**Required inputs before generation:**
- Domain name and analysis timestamp
- Risk level classification (from CLAUDE.md)
- SPF analysis results (from spf-validator.md)
- DKIM detection status (from CLAUDE.md)
- DMARC analysis results (from CLAUDE.md)
- Recommended DNS records
- Implementation steps

**Optional inputs (enhance report if available):**
- DMARC aggregate report data (from dmarc-parser.md)
- Historical analysis data (for trends)
- DNS query metadata (from dns-fetcher.md)

# Report Types

## Type 1: Security Analysis Report

**Purpose:** Primary output from single-domain analysis
**Audience:** Business owner or IT administrator
**Trigger:** Manual analysis request or first-time domain scan

**Required sections:**
1. Executive Summary
2. Security Status Dashboard
3. Risk Assessment
4. Issues and Findings
5. Recommended DNS Records
6. Implementation Guide
7. Disclaimers

## Type 2: Aggregate Report Summary

**Purpose:** Digest of DMARC aggregate reports over time
**Audience:** IT administrator, security team
**Trigger:** Periodic (weekly/monthly) or on-demand

**Required sections:**
1. Period Summary
2. Volume Statistics
3. Authentication Pass/Fail Rates
4. Sender Source Analysis
5. Trend Charts
6. Anomaly Alerts
7. Action Items

## Type 3: Executive Briefing

**Purpose:** High-level risk summary for leadership
**Audience:** Non-technical executives, compliance officers
**Trigger:** Quarterly review or incident response

**Required sections:**
1. Risk Status (single indicator)
2. Business Impact Summary (< 100 words)
3. Key Metrics (3-5 numbers)
4. Recommended Actions (prioritized)
5. Progress Since Last Report (if applicable)

## Type 4: Compliance Report

**Purpose:** Document email authentication posture for compliance
**Audience:** Compliance officers, auditors
**Trigger:** Audit preparation, regulatory requirement

**Required sections:**
1. Domain Authentication Inventory
2. Policy Configuration Status
3. RFC Compliance Assessment
4. Gap Analysis
5. Remediation Timeline
6. Evidence (DNS records, report data)

# Report Templates

## HTML Template Structure

```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>DMARC Security Report - [domain] - [date]</title>
  <style>
    /* Inline styles - Tailwind utility classes where applicable */
    /* Print-friendly styles via @media print */
  </style>
</head>
<body>
  <header>
    <!-- Report title, domain, date, report type -->
  </header>

  <nav>
    <!-- Table of contents with anchor links -->
  </nav>

  <main>
    <section id="executive-summary">
      <!-- Risk indicator, key findings, action items -->
    </section>

    <section id="security-status">
      <!-- SPF/DKIM/DMARC status dashboard -->
    </section>

    <section id="findings">
      <!-- Detailed issues with severity -->
    </section>

    <section id="recommendations">
      <!-- DNS records, implementation steps -->
    </section>

    <section id="data">
      <!-- Charts, tables, raw data (if aggregate report) -->
    </section>
  </main>

  <footer>
    <!-- Disclaimers, generation metadata, version -->
  </footer>
</body>
</html>
```

## Visual Components

### Risk Level Indicator

```html
<!-- HIGH RISK -->
<div class="risk-indicator risk-high"
     style="background: #DC2626; color: white; padding: 16px 32px;
            border-radius: 8px; font-size: 24px; font-weight: bold;
            text-align: center;">
  HIGH RISK
  <div style="font-size: 14px; font-weight: normal; margin-top: 8px;">
    Immediate action required
  </div>
</div>

<!-- MEDIUM RISK -->
<div class="risk-indicator risk-medium"
     style="background: #F59E0B; color: white; padding: 16px 32px;
            border-radius: 8px; font-size: 24px; font-weight: bold;
            text-align: center;">
  MEDIUM RISK
  <div style="font-size: 14px; font-weight: normal; margin-top: 8px;">
    Improvements recommended
  </div>
</div>

<!-- LOW RISK -->
<div class="risk-indicator risk-low"
     style="background: #10B981; color: white; padding: 16px 32px;
            border-radius: 8px; font-size: 24px; font-weight: bold;
            text-align: center;">
  LOW RISK
  <div style="font-size: 14px; font-weight: normal; margin-top: 8px;">
    Well configured
  </div>
</div>
```

### Security Status Dashboard

```html
<div class="status-grid"
     style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px;">

  <!-- SPF Status Card -->
  <div class="status-card" style="border: 2px solid [color]; border-radius: 8px; padding: 16px;">
    <div style="font-weight: bold; font-size: 14px; color: #6B7280;">SPF</div>
    <div style="font-size: 20px; font-weight: bold; color: [status-color]; margin: 8px 0;">
      [Present/Absent]
    </div>
    <div style="font-size: 12px; color: #9CA3AF;">[Detail: e.g., "Softfail (~all)"]</div>
  </div>

  <!-- DKIM Status Card -->
  <!-- Same structure as SPF -->

  <!-- DMARC Status Card -->
  <!-- Same structure as SPF -->

  <!-- Reporting Status Card -->
  <!-- Same structure as SPF -->
</div>
```

### Authentication Results Chart (for aggregate reports)

**Chart specifications:**
- Type: Stacked bar chart or donut chart
- Library: Recharts or Chart.js (per CLAUDE.md allowed libraries)
- Colors: Green (#10B981) for pass, Red (#EF4444) for fail, Yellow (#F59E0B) for partial
- Must include labels and legend
- Must be accessible (pattern fills or labels, not color-only)

**Data format for chart:**
```json
{
  "chart_type": "stacked_bar",
  "title": "Authentication Results",
  "x_axis": "Date",
  "y_axis": "Message Count",
  "series": [
    { "name": "DKIM+SPF Pass", "color": "#10B981", "data": [] },
    { "name": "DKIM Pass Only", "color": "#3B82F6", "data": [] },
    { "name": "SPF Pass Only", "color": "#F59E0B", "data": [] },
    { "name": "Both Fail", "color": "#EF4444", "data": [] }
  ]
}
```

### Sender Source Table

```html
<table style="width: 100%; border-collapse: collapse;" role="table" aria-label="Sender Sources">
  <thead>
    <tr style="background: #F3F4F6; text-align: left;">
      <th style="padding: 12px; border-bottom: 2px solid #E5E7EB;">Source IP</th>
      <th style="padding: 12px; border-bottom: 2px solid #E5E7EB;">Hostname</th>
      <th style="padding: 12px; border-bottom: 2px solid #E5E7EB;">Volume</th>
      <th style="padding: 12px; border-bottom: 2px solid #E5E7EB;">SPF</th>
      <th style="padding: 12px; border-bottom: 2px solid #E5E7EB;">DKIM</th>
      <th style="padding: 12px; border-bottom: 2px solid #E5E7EB;">Classification</th>
    </tr>
  </thead>
  <tbody>
    <!-- Rows sorted by volume descending -->
    <!-- Color-code classification: green=legitimate, yellow=forwarding, red=suspicious -->
  </tbody>
</table>
```

# Narrative Generation Standards

## Language Requirements

**For all audience types:**
- Active voice preferred
- Sentences under 25 words where possible
- No undefined acronyms (define on first use)
- Consistent terminology throughout report

**For business audience (Type 1, 3):**
- No raw technical data in narrative sections
- Technical terms explained in parentheses
- Risk quantified in business terms (financial, reputational)
- Action items clearly separated from analysis

**For technical audience (Type 2, 4):**
- Include raw DNS records and configuration details
- Reference RFC sections where relevant
- Include diagnostic commands for verification
- Provide exact values and thresholds

## Executive Summary Template

```
EXECUTIVE SUMMARY

Domain: [domain]
Analysis Date: [date]
Risk Level: [HIGH/MEDIUM/LOW]

[Domain] email security is currently rated [RISK LEVEL].

Key Findings:
- [Finding 1 - most critical]
- [Finding 2]
- [Finding 3]

Immediate Actions Required:
1. [Most urgent action] - [estimated effort]
2. [Second action] - [estimated effort]
3. [Third action] - [estimated effort]

Business Impact: [1-2 sentences on what this means for the organization]
```

## Findings Narrative Template

```
FINDING: [Title]
Severity: [Critical/High/Medium/Low]
Component: [SPF/DKIM/DMARC]

Current State:
[Description of what was observed]

Risk:
[What this means in practical terms]

Recommendation:
[Specific action to resolve]

DNS Record:
[Copy-paste ready record if applicable]

Verification:
[How to confirm the fix worked]
```

# PDF Export Standards

## PDF Generation Requirements

**Page layout:**
- Paper size: A4 or Letter (configurable)
- Margins: 25mm all sides
- Header: Report title, domain, page number
- Footer: Generation date, disclaimer reference, confidentiality notice

**Typography:**
- Headings: Sans-serif (Arial, Helvetica), bold
- Body: Sans-serif, regular, 11pt minimum
- Code/DNS records: Monospace (Courier New), 10pt
- Line height: 1.5 minimum

**Visual elements in PDF:**
- Charts rendered as static images (SVG or PNG)
- Tables with proper cell borders
- Risk indicator with color and text label (not color-dependent)
- Page breaks before major sections

**PDF metadata:**
```json
{
  "title": "DMARC Security Report - [domain]",
  "author": "DMARC Security Agent",
  "subject": "Email Authentication Security Analysis",
  "keywords": "DMARC, SPF, DKIM, email security, [domain]",
  "creator": "DMARC Security Agent v1.0",
  "created": "ISO-8601 timestamp"
}
```

## Print Stylesheet

```css
@media print {
  body { font-size: 11pt; color: #000; }
  .no-print { display: none; }
  .page-break { page-break-before: always; }
  a { color: #000; text-decoration: underline; }
  .risk-indicator { border: 3px solid currentColor; }
  table { page-break-inside: avoid; }
  thead { display: table-header-group; }
  .chart-container { page-break-inside: avoid; }
}
```

# JSON Structured Report

## Machine-Readable Output

```json
{
  "report_metadata": {
    "version": "1.0",
    "type": "security_analysis|aggregate_summary|executive_briefing|compliance",
    "domain": "example.com",
    "generated_at": "ISO-8601",
    "generator": "DMARC Security Agent",
    "data_sources": [
      "dns_query",
      "dmarc_aggregate_report",
      "historical_analysis"
    ]
  },
  "risk_assessment": {
    "level": "HIGH|MEDIUM|LOW",
    "score": 0-100,
    "factors": [
      {
        "component": "SPF|DKIM|DMARC",
        "status": "string",
        "contribution": "string"
      }
    ]
  },
  "security_status": {
    "spf": {},
    "dkim": {},
    "dmarc": {},
    "reporting": {}
  },
  "findings": [
    {
      "id": "string",
      "severity": "critical|high|medium|low",
      "component": "SPF|DKIM|DMARC",
      "title": "string",
      "description": "string",
      "remediation": "string",
      "dns_record": "string (if applicable)"
    }
  ],
  "recommendations": {
    "dns_records": [],
    "implementation_steps": [],
    "timeline": {}
  },
  "aggregate_data": {
    "statistics": {},
    "sources": [],
    "trends": {}
  }
}
```

# Accessibility Requirements

## Report Accessibility Standards

**WCAG 2.1 Level AA compliance:**
- [ ] Color is not the sole means of conveying information
- [ ] All images/charts have text alternatives
- [ ] Tables have proper headers and scope attributes
- [ ] Heading hierarchy is logical (h1 > h2 > h3)
- [ ] Link text is descriptive (no "click here")
- [ ] Contrast ratio >= 4.5:1 for text
- [ ] Contrast ratio >= 3:1 for large text and UI components
- [ ] Font size >= 11pt for body text
- [ ] Content readable at 200% zoom

**Risk indicator accessibility:**
- Always include text label with color indicator
- Use patterns/icons in addition to color
- Ensure screen reader can identify risk level
- Example: "HIGH RISK" in red box with warning icon AND text

**Table accessibility:**
```html
<table role="table" aria-label="SPF Validation Results">
  <caption>SPF record analysis showing mechanisms and their validation status</caption>
  <thead>
    <tr>
      <th scope="col">Mechanism</th>
      <th scope="col">Status</th>
    </tr>
  </thead>
</table>
```

# Branding and Customization

## Default Branding

**Color palette:**
- Primary: #1E40AF (blue-800)
- Secondary: #6B7280 (gray-500)
- Success: #10B981 (green-500)
- Warning: #F59E0B (amber-500)
- Danger: #EF4444 (red-500)
- Critical: #DC2626 (red-600)
- Background: #FFFFFF
- Text: #111827 (gray-900)

**Report header:**
```
DMARC Security Analysis
[domain] | [date] | [report-type]
```

## Custom Branding Support

**Configurable elements:**
- Logo (header position)
- Color palette (primary, secondary, accent)
- Report title prefix
- Footer text
- Contact information
- Confidentiality notice

**Branding configuration:**
```json
{
  "branding": {
    "logo_url": "optional",
    "company_name": "optional",
    "primary_color": "#1E40AF",
    "report_title_prefix": "DMARC Security Analysis",
    "footer_text": "Generated by DMARC Security Agent",
    "confidentiality": "CONFIDENTIAL - For authorized recipients only"
  }
}
```

# Integration Points

## CLAUDE.md Integration

- Receives security analysis output in required format
- Renders each CLAUDE.md section as report section
- Preserves copy-paste DNS record formatting
- Maps risk level to visual indicator

## dmarc-parser.md Integration

- Receives normalized aggregate report data
- Generates charts from statistics
- Creates sender source tables
- Displays trend analysis

## spf-validator.md Integration

- Receives SPF validation results
- Generates lookup count visualization
- Displays mechanism breakdown table
- Shows misconfiguration findings

## automation-workflow.md Integration

- Triggered by automation pipeline
- Returns report in requested format (HTML, PDF, JSON)
- Supports batch report generation
- Provides report URL or file path

# Constraints and Prohibitions

## Critical Prohibitions

**Never:**
- Generate reports with fabricated data
- Include sensitive data (passwords, API keys, PII)
- Use color as the only means of conveying information
- Generate reports without disclaimers section
- Skip data validation before rendering
- Produce reports with broken chart/table rendering
- Include raw XML or unformatted data dumps in business-facing reports

**Always:**
- Validate all data before rendering
- Include generation metadata
- Apply accessibility standards
- Include disclaimers
- Test report rendering before delivery
- Provide both human-readable and machine-readable outputs
- Ensure DNS records are copy-paste ready (no line breaks, no formatting artifacts)

# Verification Criteria

## Report Complete When

- [ ] All required sections present for report type
- [ ] Data validated against source components
- [ ] Visual elements render correctly
- [ ] Risk indicator matches analysis
- [ ] DNS records copy-paste clean
- [ ] Accessibility standards met
- [ ] Print/PDF layout verified
- [ ] No placeholder or template text remaining
- [ ] Generation metadata included
- [ ] Disclaimers present
- [ ] Narrative language appropriate for audience
- [ ] JSON output validates against schema
