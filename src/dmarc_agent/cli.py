"""DMARC Security Agent CLI. Four subcommands wired to the analysis pipeline."""

import sys
from datetime import datetime
from typing import Optional

import click
from rich.console import Console

from .dkim_checker import DkimChecker
from .dmarc_analyzer import DmarcAnalyzer
from .dns_fetcher import create_fetcher
from .exceptions import DmarcAgentError, DmarcParseError, InvalidDomainError
from .models import AnalysisResult
from .record_generator import RecordGenerator
from .report_html import HtmlReporter
from .report_json import JsonReporter
from .report_parser import ReportParser
from .report_text import TextReporter
from .risk_classifier import RiskClassifier
from .spf_validator import SpfValidator


@click.group()
@click.version_option(version="0.1.0", prog_name="dmarc-agent")
def cli():
    """DMARC Security Agent — Email authentication analysis tool.

    Analyzes SPF, DKIM, and DMARC configuration for a domain and produces
    risk assessments with actionable remediation steps.
    """


@cli.command("analyze")
@click.argument("domain")
@click.option(
    "--dkim-selector", default=None,
    help="DKIM selector to check. If omitted, DKIM presence is not verified.",
)
@click.option(
    "--format", "output_format",
    type=click.Choice(["text", "json", "html"]),
    default="text",
    show_default=True,
    help="Output format.",
)
@click.option(
    "--output", "output_file",
    default=None,
    type=click.Path(),
    help="Write output to FILE instead of stdout.",
)
def analyze(domain: str, dkim_selector: Optional[str], output_format: str, output_file: Optional[str]):
    """Full analysis: SPF + DMARC + optional DKIM for DOMAIN."""
    try:
        fetcher = create_fetcher()
        result = _run_full_analysis(domain, dkim_selector, fetcher, quiet=(output_format != "text"))
        _dispatch_output(result, output_format, output_file)
    except InvalidDomainError as e:
        click.echo(f"Error: Invalid domain — {e}", err=True)
        sys.exit(1)
    except DmarcAgentError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@cli.command("check-spf")
@click.argument("domain")
def check_spf(domain: str):
    """Quick SPF-only validation for DOMAIN."""
    try:
        fetcher = create_fetcher()
        validator = SpfValidator(fetcher)
        result = validator.validate(domain)
        TextReporter().render_spf_only(result)
    except DmarcAgentError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@cli.command("check-dmarc")
@click.argument("domain")
def check_dmarc(domain: str):
    """Quick DMARC-only policy evaluation for DOMAIN."""
    try:
        fetcher = create_fetcher()
        analyzer = DmarcAnalyzer(fetcher)
        result = analyzer.analyze(domain)
        TextReporter().render_dmarc_only(result)
    except DmarcAgentError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@cli.command("verify-dkim")
@click.argument("selector")
@click.argument("domain")
def verify_dkim(selector: str, domain: str):
    """Check one explicit DKIM SELECTOR for DOMAIN."""
    try:
        fetcher = create_fetcher()
        checker = DkimChecker(fetcher)
        result = checker.check(domain, selector)
        TextReporter().render_dkim_only(result)
    except DmarcAgentError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@cli.command("serve")
@click.option("--host", default="0.0.0.0", show_default=True, help="Bind address.")
@click.option("--port", default=8000, show_default=True, type=int, help="Listen port.")
@click.option(
    "--api-key",
    envvar="DMARC_API_KEY",
    required=True,
    help="Bearer token for API authentication. Also read from DMARC_API_KEY env var.",
)
@click.option("--workers", default=4, show_default=True, type=int, help="Uvicorn worker count.")
def serve(host: str, port: int, api_key: str, workers: int):
    """Start the REST API server for n8n automation.

    Requires the [api] optional dependencies:

        pip install 'dmarc-agent[api]'

    The DMARC_API_KEY environment variable (or --api-key flag) sets the
    Bearer token that n8n must supply in the Authorization header.
    """
    try:
        import uvicorn  # noqa: PLC0415
    except ImportError:
        click.echo(
            "Error: uvicorn is not installed. Run: pip install 'dmarc-agent[api]'",
            err=True,
        )
        sys.exit(1)

    import os  # noqa: PLC0415

    os.environ["DMARC_API_KEY"] = api_key
    click.echo(f"Starting DMARC API server on http://{host}:{port}", err=True)
    click.echo(f"API docs: http://{host}:{port}/docs", err=True)
    uvicorn.run(
        "dmarc_agent.api_server:app",
        host=host,
        port=port,
        workers=workers,
        log_level="info",
    )


@cli.command("parse-report")
@click.argument("file", type=click.Path(exists=True))
@click.option(
    "--format", "output_format",
    type=click.Choice(["text", "json"]),
    default="text",
    show_default=True,
    help="Output format.",
)
@click.option(
    "--output", "output_file",
    default=None,
    type=click.Path(),
    help="Write output to FILE instead of stdout.",
)
def parse_report(file: str, output_format: str, output_file: Optional[str]):
    """Parse a DMARC aggregate XML report file (supports .xml, .xml.gz, .zip)."""
    try:
        parsed = ReportParser().parse_file(file)

        if output_format == "json":
            output = JsonReporter().render_parsed_report(parsed)
            if output_file:
                _write_file(output_file, output)
                click.echo(f"Report written to: {output_file}", err=True)
            else:
                click.echo(output)
        else:
            if output_file:
                from rich.console import Console as RichConsole
                with open(output_file, "w", encoding="utf-8") as f:
                    plain_console = RichConsole(file=f, highlight=False, no_color=True)
                    TextReporter(console=plain_console).render_parsed_report(parsed)
                click.echo(f"Report written to: {output_file}", err=True)
            else:
                TextReporter().render_parsed_report(parsed)

    except DmarcParseError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)
    except DmarcAgentError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


# ── Orchestration ──────────────────────────────────────────────────────────────

def _run_full_analysis(domain: str, dkim_selector: Optional[str], fetcher, quiet: bool = False) -> AnalysisResult:
    """
    Mandatory 8-step analysis sequence from CLAUDE.md:
    1. Parse SPF
    2. Check DKIM (if selector provided)
    3. Parse DMARC
    4. Classify risk
    5. Generate remediation records
    6. Generate client explanation
    7. Build implementation phases (inside RecordGenerator)
    8. Return AnalysisResult
    """
    console = Console(stderr=True)

    if not quiet:
        console.print(f"[dim]Fetching SPF record for {domain}...[/dim]", highlight=False)
    spf = SpfValidator(fetcher).validate(domain)

    if not quiet:
        console.print(f"[dim]Checking DKIM{f' (selector: {dkim_selector})' if dkim_selector else ''}...[/dim]", highlight=False)
    dkim = DkimChecker(fetcher).check(domain, dkim_selector)

    if not quiet:
        console.print(f"[dim]Fetching DMARC record for {domain}...[/dim]", highlight=False)
    dmarc = DmarcAnalyzer(fetcher).analyze(domain)

    risk = RiskClassifier().classify(spf, dkim, dmarc)
    generator = RecordGenerator()
    plan = generator.generate(domain, spf, dkim, dmarc)
    explanation = generator.generate_client_explanation(risk, domain)

    return AnalysisResult(
        domain=domain,
        analyzed_at=datetime.utcnow(),
        spf=spf,
        dkim=dkim,
        dmarc=dmarc,
        risk=risk,
        remediation=plan,
        client_explanation=explanation,
    )


def _dispatch_output(result: AnalysisResult, output_format: str, output_file: Optional[str]) -> None:
    """Route the result to the appropriate reporter."""
    if output_format == "json":
        output = JsonReporter().render(result)
        if output_file:
            _write_file(output_file, output)
        else:
            click.echo(output)

    elif output_format == "html":
        output = HtmlReporter().render(result)
        if output_file:
            _write_file(output_file, output)
            click.echo(f"Report written to: {output_file}", err=True)
        else:
            click.echo(output)

    else:  # text
        if output_file:
            from rich.console import Console as RichConsole
            with open(output_file, "w", encoding="utf-8") as f:
                plain_console = RichConsole(file=f, highlight=False, no_color=True)
                TextReporter(console=plain_console).render(result)
            click.echo(f"Report written to: {output_file}", err=True)
        else:
            TextReporter().render(result)


def _write_file(path: str, content: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
