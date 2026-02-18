"""JSON serializer matching the CLAUDE.md automation output schema."""

import json
from datetime import datetime

from .models import AnalysisResult, DkimResult, DmarcResult, Issue, ParsedReport, SpfResult


class JsonReporter:
    def render(self, result: AnalysisResult) -> str:
        return json.dumps(self._to_dict(result), indent=2, default=str)

    def _to_dict(self, result: AnalysisResult) -> dict:
        return {
            "domain": result.domain,
            "timestamp": result.analyzed_at.isoformat() + "Z",
            "risk_level": result.risk.level.value,
            "security_status": {
                "spf": self._spf_status(result.spf),
                "dkim": self._dkim_status(result.dkim),
                "dmarc": self._dmarc_status(result.dmarc),
            },
            "recommended_records": self._recommended_records(result),
            "findings": [self._issue_dict(i) for i in result.risk.issues],
            "implementation_priority": [
                p.title for p in result.remediation.implementation_phases
            ],
            "business_impact": result.client_explanation,
            "next_steps": self._next_steps(result),
        }

    def _spf_status(self, spf: SpfResult) -> dict:
        return {
            "present": spf.present,
            "raw_record": spf.raw_record,
            "all_qualifier": spf.all_qualifier.value if spf.all_qualifier else None,
            "total_lookups": spf.total_lookups,
            "lookup_limit_status": spf.lookup_limit_status,
            "risk_contribution": spf.risk_contribution,
            "duplicate_records": spf.duplicate_records,
            "issues": [
                {
                    "id": m.id,
                    "severity": m.severity,
                    "description": m.description,
                    "remediation": m.remediation,
                }
                for m in spf.misconfigurations
            ],
        }

    def _dkim_status(self, dkim: DkimResult) -> dict:
        return {
            "checked": dkim.checked,
            "selector": dkim.selector,
            "present": dkim.present,
            "risk_contribution": dkim.risk_contribution,
        }

    def _dmarc_status(self, dmarc: DmarcResult) -> dict:
        return {
            "present": dmarc.present,
            "raw_record": dmarc.raw_record,
            "policy": dmarc.policy.value if dmarc.policy else None,
            "subdomain_policy": dmarc.subdomain_policy.value if dmarc.subdomain_policy else None,
            "rua": dmarc.rua,
            "ruf": dmarc.ruf,
            "fo": dmarc.fo,
            "pct": dmarc.pct,
            "progression_stage": dmarc.progression_stage,
            "risk_contribution": dmarc.risk_contribution,
            "issues": dmarc.issues,
        }

    def _recommended_records(self, result: AnalysisResult) -> dict:
        plan = result.remediation
        return {
            "spf": plan.spf.value if plan.spf else None,
            "dmarc": plan.dmarc.value if plan.dmarc else None,
            "dkim": plan.dkim_action or "no_action_required" if not result.dkim.present else "present",
        }

    def _issue_dict(self, issue: Issue) -> dict:
        return {
            "id": issue.id,
            "component": issue.component,
            "severity": issue.severity,
            "title": issue.title,
            "description": issue.description,
            "remediation": issue.remediation,
            "priority": issue.priority,
        }

    def _next_steps(self, result: AnalysisResult) -> list:
        steps = []
        for phase in result.remediation.implementation_phases:
            if phase.steps:
                steps.append(phase.steps[0])  # First action of each phase
        return steps

    # ── Parsed report serializer ───────────────────────────────────────────────

    def render_parsed_report(self, report: ParsedReport) -> str:
        return json.dumps(self._parsed_to_dict(report), indent=2, default=str)

    def _parsed_to_dict(self, report: ParsedReport) -> dict:
        m = report.metadata
        p = report.policy_published
        s = report.statistics
        return {
            "parse_metadata": {
                "parser_version": "1.0",
                "parsed_at": report.parsed_at.isoformat() + "Z",
                "validation_status": "warnings" if report.validation_messages else "valid",
                "validation_messages": report.validation_messages,
            },
            "report": {
                "metadata": {
                    "org_name": m.org_name,
                    "email": m.email,
                    "report_id": m.report_id,
                    "date_range": {
                        "begin": m.begin.isoformat(),
                        "end": m.end.isoformat(),
                        "duration_hours": round(m.duration_hours, 1),
                    },
                    "extra_contact_info": m.extra_contact_info,
                },
                "policy_published": {
                    "domain": p.domain,
                    "adkim": p.adkim,
                    "aspf": p.aspf,
                    "policy": p.policy,
                    "subdomain_policy": p.subdomain_policy,
                    "pct": p.pct,
                },
                "statistics": {
                    "total_messages": s.total_messages,
                    "dkim_pass": s.dkim_pass,
                    "dkim_fail": s.dkim_fail,
                    "spf_pass": s.spf_pass,
                    "spf_fail": s.spf_fail,
                    "fully_aligned": s.fully_aligned,
                    "fully_failed": s.fully_failed,
                    "disposition_none": s.disposition_none,
                    "disposition_quarantine": s.disposition_quarantine,
                    "disposition_reject": s.disposition_reject,
                    "unique_sources": s.unique_sources,
                    "pass_rate_dkim": s.pass_rate_dkim,
                    "pass_rate_spf": s.pass_rate_spf,
                    "pass_rate_overall": s.pass_rate_overall,
                },
                "source_classifications": [
                    {
                        "source_ip": sc.source_ip,
                        "classification": sc.classification,
                        "confidence": sc.confidence,
                        "evidence": sc.evidence,
                        "message_count": sc.message_count,
                        "pass_rate": sc.pass_rate,
                    }
                    for sc in report.source_classifications
                ],
                "records": [
                    {
                        "source_ip": r.source_ip,
                        "count": r.count,
                        "policy_evaluated": {
                            "disposition": r.policy_evaluated.disposition,
                            "dkim": r.policy_evaluated.dkim,
                            "spf": r.policy_evaluated.spf,
                        },
                        "header_from": r.header_from,
                        "envelope_from": r.envelope_from,
                        "dkim_auth": [
                            {"domain": d.domain, "selector": d.selector, "result": d.result}
                            for d in r.dkim_auth
                        ],
                        "spf_auth": [
                            {"domain": d.domain, "scope": d.scope, "result": d.result}
                            for d in r.spf_auth
                        ],
                    }
                    for r in report.records
                ],
            },
            "risk_indicators": {
                "unauthorized_senders": sum(
                    1 for sc in report.source_classifications if sc.classification == "suspicious"
                ),
                "authentication_failures": s.fully_failed,
                "spoofing_attempts": sum(
                    sc.message_count for sc in report.source_classifications
                    if sc.classification == "suspicious"
                ),
            },
            "recommendations": report.recommendations,
        }
