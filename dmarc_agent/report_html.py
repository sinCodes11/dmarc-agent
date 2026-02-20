"""HTML report generator. Inline CSS only, WCAG 2.1 AA compliant."""

from datetime import datetime

from .models import AnalysisResult, DmarcPolicy, Issue, RiskLevel, SpfQualifier
from .record_generator import DISCLAIMERS

RISK_COLORS = {
    RiskLevel.HIGH:   "#DC2626",
    RiskLevel.MEDIUM: "#F59E0B",
    RiskLevel.LOW:    "#10B981",
}

SEVERITY_COLORS = {
    "critical": "#DC2626",
    "high":     "#EF4444",
    "medium":   "#F59E0B",
    "low":      "#3B82F6",
}

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>DMARC Security Report - {domain} - {date}</title>
  <style>
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{ font-family: Arial, Helvetica, sans-serif; font-size: 14px; line-height: 1.6;
            color: #111827; background: #F9FAFB; padding: 24px; }}
    .container {{ max-width: 960px; margin: 0 auto; background: #fff;
                  border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,.1); }}
    header {{ background: #1E40AF; color: #fff; padding: 24px 32px; border-radius: 8px 8px 0 0; }}
    header h1 {{ font-size: 24px; font-weight: 700; }}
    header p {{ margin-top: 4px; opacity: .85; font-size: 13px; }}
    main {{ padding: 32px; }}
    h2 {{ font-size: 18px; font-weight: 700; color: #1E40AF; border-bottom: 2px solid #E5E7EB;
          padding-bottom: 8px; margin: 32px 0 16px; }}
    h2:first-child {{ margin-top: 0; }}
    h3 {{ font-size: 15px; font-weight: 600; color: #374151; margin: 20px 0 8px; }}
    .risk-badge {{ display: inline-block; padding: 12px 24px; border-radius: 6px;
                   font-size: 20px; font-weight: 700; color: #fff;
                   background: {risk_color}; margin: 8px 0; }}
    .risk-justification {{ margin-top: 12px; }}
    .risk-justification li {{ margin: 4px 0 4px 20px; }}
    .status-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                    gap: 16px; margin: 16px 0; }}
    .status-card {{ border: 2px solid #E5E7EB; border-radius: 8px; padding: 16px; }}
    .status-card h4 {{ font-size: 13px; font-weight: 600; color: #6B7280;
                        text-transform: uppercase; letter-spacing: .05em; margin-bottom: 8px; }}
    .status-card .value {{ font-size: 15px; font-weight: 600; }}
    .status-ok {{ border-color: #10B981; }}
    .status-warn {{ border-color: #F59E0B; }}
    .status-bad {{ border-color: #EF4444; }}
    .status-ok .value {{ color: #065F46; }}
    .status-warn .value {{ color: #92400E; }}
    .status-bad .value {{ color: #991B1B; }}
    table {{ width: 100%; border-collapse: collapse; margin: 12px 0; font-size: 13px; }}
    table caption {{ text-align: left; font-weight: 600; margin-bottom: 8px; color: #374151; }}
    th {{ background: #F3F4F6; text-align: left; padding: 10px 12px; font-weight: 600;
          border-bottom: 2px solid #D1D5DB; }}
    td {{ padding: 10px 12px; border-bottom: 1px solid #E5E7EB; vertical-align: top; }}
    tr:last-child td {{ border-bottom: none; }}
    .sev-badge {{ display: inline-block; padding: 2px 8px; border-radius: 4px;
                  font-size: 11px; font-weight: 700; color: #fff; }}
    .dns-record {{ background: #1F2937; color: #F9FAFB; font-family: "Courier New", monospace;
                   font-size: 13px; padding: 16px; border-radius: 6px; word-break: break-all;
                   white-space: pre-wrap; margin: 8px 0; border-left: 4px solid #10B981; }}
    .record-block {{ background: #F9FAFB; border: 1px solid #E5E7EB; border-radius: 6px;
                     padding: 16px; margin: 16px 0; }}
    .record-block .label {{ font-size: 12px; color: #6B7280; font-weight: 600;
                             text-transform: uppercase; margin-bottom: 4px; }}
    .record-block .field {{ margin: 8px 0; }}
    .explanation {{ background: #EFF6FF; border-left: 4px solid #3B82F6;
                    padding: 16px; border-radius: 0 6px 6px 0; white-space: pre-wrap;
                    line-height: 1.7; }}
    .phase {{ background: #F9FAFB; border: 1px solid #E5E7EB; border-radius: 6px;
              padding: 16px; margin: 12px 0; }}
    .phase h4 {{ font-size: 14px; font-weight: 700; color: #1E40AF; margin-bottom: 8px; }}
    .phase ol {{ padding-left: 20px; }}
    .phase li {{ margin: 4px 0; font-size: 13px; }}
    .phase .timeline {{ font-size: 12px; color: #6B7280; margin-top: 8px; }}
    .phase .verify {{ font-family: "Courier New", monospace; font-size: 12px;
                      background: #F3F4F6; padding: 4px 8px; border-radius: 4px;
                      display: inline-block; margin-top: 6px; }}
    .disclaimer {{ background: #FFFBEB; border: 1px solid #F59E0B; border-radius: 6px;
                   padding: 16px; white-space: pre-wrap; font-size: 13px; line-height: 1.7; }}
    footer {{ background: #F3F4F6; padding: 16px 32px; border-radius: 0 0 8px 8px;
              font-size: 12px; color: #6B7280; }}
    @media print {{
      body {{ background: #fff; padding: 0; }}
      .container {{ box-shadow: none; }}
      .dns-record {{ background: #1F2937 !important; color: #F9FAFB !important; }}
      h2 {{ page-break-after: avoid; }}
      .phase {{ page-break-inside: avoid; }}
      table {{ page-break-inside: avoid; }}
    }}
  </style>
</head>
<body>
<div class="container">
  <header>
    <h1>DMARC Security Report</h1>
    <p>Domain: {domain} &nbsp;|&nbsp; Generated: {date} &nbsp;|&nbsp; Analysis by DMARC Security Agent</p>
  </header>
  <main>

    <h2>SECURITY STATUS</h2>
    <div class="status-grid">
      {status_cards}
    </div>

    <h2>RISK LEVEL</h2>
    <div class="risk-badge" role="img" aria-label="{risk_level} risk">{risk_level} RISK</div>
    <div class="risk-justification">
      <ul>
        {risk_justification}
      </ul>
    </div>

    <h2>ISSUES FOUND</h2>
    {issues_table}

    <h2>RECOMMENDED RECORDS</h2>
    {recommended_records}

    <h2>CLIENT EXPLANATION</h2>
    <div class="explanation">{client_explanation}</div>

    <h2>IMPLEMENTATION STEPS</h2>
    {implementation_steps}

    <h2>DISCLAIMERS</h2>
    <div class="disclaimer">{disclaimers}</div>

  </main>
  <footer>
    Generated by DMARC Security Agent v0.1.0 &nbsp;|&nbsp; {date} &nbsp;|&nbsp;
    Analysis based on DNS state at time of query.
  </footer>
</div>
</body>
</html>"""


class HtmlReporter:
    def render(self, result: AnalysisResult) -> str:
        risk_color = RISK_COLORS.get(result.risk.level, "#6B7280")
        date_str = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

        return HTML_TEMPLATE.format(
            domain=_escape(result.domain),
            date=date_str,
            risk_color=risk_color,
            risk_level=result.risk.level.value,
            status_cards=self._render_status_cards(result),
            risk_justification=self._render_risk_justification(result.risk.justification),
            issues_table=self._render_issues_table(result.risk.issues),
            recommended_records=self._render_recommended_records(result),
            client_explanation=_escape(result.client_explanation),
            implementation_steps=self._render_phases(result.remediation.implementation_phases),
            disclaimers=_escape(DISCLAIMERS),
        )

    def _render_status_cards(self, result: AnalysisResult) -> str:
        spf = result.spf
        dkim = result.dkim
        dmarc = result.dmarc

        # SPF card
        if not spf.present:
            spf_cls, spf_val = "status-bad", "Absent"
        elif spf.all_qualifier == SpfQualifier.FAIL:
            spf_cls, spf_val = "status-ok", "Hard fail (-all)"
        elif spf.all_qualifier == SpfQualifier.SOFTFAIL:
            spf_cls, spf_val = "status-warn", "Softfail (~all)"
        else:
            spf_cls, spf_val = "status-bad", "Pass-all (critical)"

        # DKIM card
        if not dkim.checked:
            dkim_cls, dkim_val = "status-warn", "Not checked"
        elif dkim.present:
            dkim_cls, dkim_val = "status-ok", f"Present ({dkim.selector})"
        else:
            dkim_cls, dkim_val = "status-bad", "Not found"

        # DMARC card
        if not dmarc.present:
            dmarc_cls, dmarc_val = "status-bad", "Absent"
        elif dmarc.policy == DmarcPolicy.REJECT:
            dmarc_cls, dmarc_val = "status-ok", "p=reject"
        elif dmarc.policy == DmarcPolicy.QUARANTINE:
            dmarc_cls, dmarc_val = "status-ok", "p=quarantine"
        else:
            dmarc_cls, dmarc_val = "status-warn", "p=none (monitoring)"

        # Reporting card
        if dmarc.rua:
            rep_cls, rep_val = "status-ok", "Configured"
        else:
            rep_cls, rep_val = "status-warn", "Not configured"

        cards = [
            ("SPF", spf_cls, spf_val),
            ("DKIM", dkim_cls, dkim_val),
            ("DMARC", dmarc_cls, dmarc_val),
            ("Reporting", rep_cls, rep_val),
        ]

        html = ""
        for title, cls, val in cards:
            html += f"""
      <div class="status-card {cls}" role="region" aria-label="{title} status">
        <h4>{title}</h4>
        <div class="value">{_escape(val)}</div>
      </div>"""
        return html

    def _render_risk_justification(self, justification: list) -> str:
        if not justification:
            return ""
        return "".join(f"<li>{_escape(j)}</li>" for j in justification)

    def _render_issues_table(self, issues: list) -> str:
        if not issues:
            return "<p style='color:#065F46'>No significant issues detected.</p>"

        rows = ""
        for i, issue in enumerate(issues, 1):
            color = SEVERITY_COLORS.get(issue.severity, "#6B7280")
            rows += f"""
        <tr>
          <td>{i}</td>
          <td>{_escape(issue.component)}</td>
          <td><span class="sev-badge" style="background:{color}">{_escape(issue.severity.upper())}</span></td>
          <td>{_escape(issue.description)}</td>
          <td>{_escape(issue.remediation)}</td>
        </tr>"""

        return f"""
    <table role="table" aria-label="Security issues found">
      <caption>Issues ordered by priority</caption>
      <thead>
        <tr>
          <th scope="col">#</th>
          <th scope="col">Component</th>
          <th scope="col">Severity</th>
          <th scope="col">Description</th>
          <th scope="col">Remediation</th>
        </tr>
      </thead>
      <tbody>{rows}
      </tbody>
    </table>"""

    def _render_recommended_records(self, result: AnalysisResult) -> str:
        plan = result.remediation
        html = ""

        if plan.dmarc:
            stage_info = f"Stage {plan.dmarc.stage}/4 — " if plan.dmarc.stage else ""
            html += f"""
    <div class="record-block">
      <h3>DMARC Record</h3>
      <div class="field"><span class="label">Type</span> TXT</div>
      <div class="field"><span class="label">Name/Host</span> {_escape(plan.dmarc.name)}</div>
      <div class="field"><span class="label">Value</span>
        <div class="dns-record">{_escape(plan.dmarc.value)}</div>
      </div>
      <div class="field"><span class="label">Purpose</span> {stage_info}{_escape(plan.dmarc.purpose)}</div>
      {"<div class='field'><span class='label'>Next step</span> " + _escape(plan.dmarc.next_step) + "</div>" if plan.dmarc.next_step else ""}
    </div>"""

        if plan.spf:
            html += f"""
    <div class="record-block">
      <h3>SPF Record</h3>
      <div class="field"><span class="label">Type</span> TXT</div>
      <div class="field"><span class="label">Name/Host</span> {_escape(plan.spf.name)} (root domain)</div>
      <div class="field"><span class="label">Value</span>
        <div class="dns-record">{_escape(plan.spf.value)}</div>
      </div>
      <div class="field"><span class="label">Purpose</span> {_escape(plan.spf.purpose)}</div>
    </div>"""

        if plan.dkim_action:
            html += f"""
    <div class="record-block">
      <h3>DKIM Record</h3>
      <div class="field"><span class="label">Status</span>
        <strong style="color:#F59E0B">Requires email provider action</strong>
      </div>
      <div class="field"><span class="label">Action</span> {_escape(plan.dkim_action)}</div>
    </div>"""

        if not html:
            html = "<p style='color:#065F46'>No DNS changes required — configuration is complete.</p>"

        return html

    def _render_phases(self, phases: list) -> str:
        if not phases:
            return "<p style='color:#065F46'>No implementation steps required.</p>"

        html = ""
        for phase in phases:
            steps_html = "".join(
                f"<li>{_escape(s)}</li>" for s in phase.steps
            )
            html += f"""
    <div class="phase">
      <h4>Phase {phase.phase}: {_escape(phase.title)}</h4>
      <ol>{steps_html}</ol>
      <div class="timeline">Timeline: {_escape(phase.timeline)}</div>
      <div>Verify: <span class="verify">{_escape(phase.verification)}</span></div>
    </div>"""

        return html


def _escape(text: str) -> str:
    """Minimal HTML escaping."""
    if not text:
        return ""
    return (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )
