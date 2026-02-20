"""Orchestrates dmarc_agent analysis pipeline for the web API."""

import json
from datetime import datetime
from typing import Optional

from dmarc_agent.dkim_checker import DkimChecker
from dmarc_agent.dmarc_analyzer import DmarcAnalyzer
from dmarc_agent.dns_fetcher import create_fetcher
from dmarc_agent.exceptions import DmarcAgentError
from dmarc_agent.models import AnalysisResult
from dmarc_agent.record_generator import RecordGenerator
from dmarc_agent.report_html import HtmlReporter
from dmarc_agent.report_json import JsonReporter
from dmarc_agent.risk_classifier import RiskClassifier
from dmarc_agent.spf_validator import SpfValidator


def run_scan(domain: str, dkim_selector: Optional[str] = None) -> dict:
    """Run full DMARC analysis. Returns dict matching JsonReporter schema."""
    fetcher = create_fetcher()

    spf = SpfValidator(fetcher).validate(domain)
    dkim = DkimChecker(fetcher).check(domain, dkim_selector)
    dmarc = DmarcAnalyzer(fetcher).analyze(domain)
    risk = RiskClassifier().classify(spf, dkim, dmarc)

    generator = RecordGenerator()
    plan = generator.generate(domain, spf, dkim, dmarc)
    explanation = generator.generate_client_explanation(risk, domain)

    result = AnalysisResult(
        domain=domain,
        analyzed_at=datetime.utcnow(),
        spf=spf,
        dkim=dkim,
        dmarc=dmarc,
        risk=risk,
        remediation=plan,
        client_explanation=explanation,
    )

    return json.loads(JsonReporter().render(result))


def render_html_report(domain: str) -> str:
    """Re-run analysis and return full HTML report for email delivery."""
    try:
        fetcher = create_fetcher()

        spf = SpfValidator(fetcher).validate(domain)
        dkim = DkimChecker(fetcher).check(domain, None)
        dmarc = DmarcAnalyzer(fetcher).analyze(domain)
        risk = RiskClassifier().classify(spf, dkim, dmarc)

        generator = RecordGenerator()
        plan = generator.generate(domain, spf, dkim, dmarc)
        explanation = generator.generate_client_explanation(risk, domain)

        result = AnalysisResult(
            domain=domain,
            analyzed_at=datetime.utcnow(),
            spf=spf,
            dkim=dkim,
            dmarc=dmarc,
            risk=risk,
            remediation=plan,
            client_explanation=explanation,
        )
        return HtmlReporter().render(result)

    except DmarcAgentError as e:
        return f"<html><body><h1>Report unavailable</h1><p>{e}</p></body></html>"
