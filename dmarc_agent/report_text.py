"""Rich terminal renderer. Uses exact section headers from CLAUDE.md."""

from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

from .models import (
    AnalysisResult,
    DkimResult,
    DmarcResult,
    DmarcPolicy,
    Issue,
    ParsedReport,
    RemediationPlan,
    RiskAssessment,
    RiskLevel,
    SpfQualifier,
    SpfResult,
)
from .record_generator import DISCLAIMERS

RISK_STYLE = {
    RiskLevel.HIGH:   "bold white on red",
    RiskLevel.MEDIUM: "bold white on dark_orange",
    RiskLevel.LOW:    "bold white on green",
}

SEVERITY_STYLE = {
    "critical": "bold red",
    "high":     "red",
    "medium":   "yellow",
    "low":      "blue",
}


class TextReporter:
    def __init__(self, console: Optional[Console] = None):
        self._console = console or Console()

    def render(self, result: AnalysisResult) -> None:
        c = self._console
        c.print()
        c.print(Panel(
            f"[bold]SECURITY ANALYSIS: {result.domain.upper()}[/bold]",
            style="bold blue",
            expand=False,
        ))

        self._render_security_status(result)
        self._render_risk_level(result.risk)
        self._render_issues(result.risk.issues)
        self._render_recommended_records(result.remediation, result.domain)
        self._render_client_explanation(result.client_explanation)
        self._render_implementation_steps(result.remediation.implementation_phases)
        self._render_disclaimers()

    # ── Individual section renderers (also usable for subcommands) ─────────────

    def render_spf_only(self, spf: SpfResult) -> None:
        c = self._console
        c.print()
        c.print(Panel(f"[bold]SPF ANALYSIS: {spf.domain.upper()}[/bold]", style="bold blue", expand=False))
        c.print(f"\n[bold]Record:[/bold] {spf.raw_record or 'Not found'}")
        c.print(f"[bold]Lookups:[/bold] {spf.total_lookups}/10 ({spf.lookup_limit_status})")
        c.print(f"[bold]Risk contribution:[/bold] {spf.risk_contribution.upper()}")
        if spf.misconfigurations:
            c.print("\n[bold yellow]Issues:[/bold yellow]")
            for mc in spf.misconfigurations:
                c.print(f"  [{SEVERITY_STYLE.get(mc.severity, 'white')}][{mc.id}][/] {mc.description}")
        if spf.recommended_record:
            c.print(f"\n[bold green]Recommended record:[/bold green]")
            c.print(Text(spf.recommended_record, no_wrap=True, style="bold"))

    def render_dmarc_only(self, dmarc: DmarcResult) -> None:
        c = self._console
        c.print()
        c.print(Panel(f"[bold]DMARC ANALYSIS: {dmarc.domain.upper()}[/bold]", style="bold blue", expand=False))
        c.print(f"\n[bold]Record:[/bold] {dmarc.raw_record or 'Not found'}")
        if dmarc.policy:
            c.print(f"[bold]Policy:[/bold] {dmarc.policy.value}")
        c.print(f"[bold]Stage:[/bold] {dmarc.progression_stage}/4")
        c.print(f"[bold]Risk contribution:[/bold] {dmarc.risk_contribution.upper()}")
        if dmarc.issues:
            c.print("\n[bold yellow]Issues:[/bold yellow]")
            for issue in dmarc.issues:
                c.print(f"  • {issue}")
        if dmarc.recommended_record:
            c.print(f"\n[bold green]Recommended next record:[/bold green]")
            c.print(Text(dmarc.recommended_record, no_wrap=True, style="bold"))

    def render_dkim_only(self, dkim: DkimResult) -> None:
        c = self._console
        c.print()
        c.print(Panel(f"[bold]DKIM CHECK: {dkim.domain.upper()}[/bold]", style="bold blue", expand=False))
        if not dkim.checked:
            c.print("\n[yellow]No selector provided — DKIM not checked.[/yellow]")
            return
        status = "[green]Present[/green]" if dkim.present else "[red]Not found[/red]"
        c.print(f"\n[bold]Selector:[/bold] {dkim.selector}")
        c.print(f"[bold]Status:[/bold] {status}")
        if dkim.present and dkim.raw_record:
            c.print(f"[bold]Record:[/bold] {dkim.raw_record[:80]}{'...' if len(dkim.raw_record) > 80 else ''}")

    # ── Section Renderers ──────────────────────────────────────────────────────

    def _render_security_status(self, result: AnalysisResult) -> None:
        c = self._console
        c.print("\n[bold]## SECURITY STATUS[/bold]")

        spf = result.spf
        dkim = result.dkim
        dmarc = result.dmarc

        # SPF
        if not spf.present:
            spf_status = "[red]Absent[/red]"
        elif spf.all_qualifier == SpfQualifier.FAIL:
            spf_status = "[green]Present — Hard fail (-all)[/green]"
        elif spf.all_qualifier == SpfQualifier.SOFTFAIL:
            spf_status = "[yellow]Present — Softfail (~all)[/yellow]"
        elif spf.all_qualifier in (SpfQualifier.PASS, SpfQualifier.NEUTRAL):
            spf_status = "[red]Present — PASS-ALL (critical misconfiguration)[/red]"
        else:
            spf_status = "[yellow]Present — qualifier unknown[/yellow]"

        # DKIM
        if not dkim.checked:
            dkim_status = "[yellow]Not checked (no selector provided)[/yellow]"
        elif dkim.present:
            dkim_status = f"[green]Confirmed present (selector: {dkim.selector})[/green]"
        else:
            dkim_status = f"[red]Not detected (selector: {dkim.selector})[/red]"

        # DMARC
        if not dmarc.present:
            dmarc_status = "[red]Absent[/red]"
        else:
            policy_color = {
                DmarcPolicy.NONE: "yellow",
                DmarcPolicy.QUARANTINE: "blue",
                DmarcPolicy.REJECT: "green",
            }.get(dmarc.policy, "white")
            dmarc_status = f"[{policy_color}]Present — p={dmarc.policy.value if dmarc.policy else '?'}[/{policy_color}]"

        rua_status = "[green]Configured[/green]" if dmarc.rua else "[yellow]Not configured[/yellow]"
        ruf_status = "[green]Configured[/green]" if dmarc.ruf else "[yellow]Not configured[/yellow]"

        c.print(f"- SPF Record: {spf_status}")
        c.print(f"- DKIM: {dkim_status}")
        c.print(f"- DMARC Record: {dmarc_status}")
        c.print(f"- Aggregate Reporting (rua): {rua_status}")
        c.print(f"- Forensic Reporting (ruf): {ruf_status}")

    def _render_risk_level(self, risk: RiskAssessment) -> None:
        c = self._console
        c.print("\n[bold]## RISK LEVEL[/bold]")
        style = RISK_STYLE.get(risk.level, "bold white")
        c.print(Panel(f" {risk.level.value} RISK ", style=style, expand=False))
        if risk.justification:
            for reason in risk.justification:
                c.print(f"  • {reason}")

    def _render_issues(self, issues: list) -> None:
        c = self._console
        c.print("\n[bold]## ISSUES FOUND[/bold]")
        if not issues:
            c.print("[green]No significant issues detected.[/green]")
            return

        table = Table(box=box.SIMPLE, show_header=True, header_style="bold")
        table.add_column("#", style="dim", width=3)
        table.add_column("Component", width=8)
        table.add_column("Severity", width=10)
        table.add_column("Issue")
        table.add_column("Remediation")

        for i, issue in enumerate(issues, 1):
            sev_style = SEVERITY_STYLE.get(issue.severity, "white")
            table.add_row(
                str(i),
                issue.component,
                f"[{sev_style}]{issue.severity.upper()}[/{sev_style}]",
                issue.description,
                issue.remediation,
            )

        c.print(table)

    def _render_recommended_records(self, plan: RemediationPlan, domain: str) -> None:
        c = self._console
        c.print("\n[bold]## RECOMMENDED RECORDS[/bold]")

        if plan.dmarc:
            c.print("\n[bold cyan]### DMARC Record[/bold cyan]")
            c.print(f"Type: TXT")
            c.print(f"Name: {plan.dmarc.name}")
            c.print(f"Value: ", end="")
            c.print(Text(plan.dmarc.value, no_wrap=True, style="bold green"))
            c.print(f"Purpose: {plan.dmarc.purpose}")
            if plan.dmarc.stage:
                c.print(f"Stage: {plan.dmarc.stage}/4")
            if plan.dmarc.next_step:
                c.print(f"Next step: {plan.dmarc.next_step}")

        if plan.spf:
            c.print("\n[bold cyan]### SPF Record[/bold cyan]")
            c.print(f"Type: TXT")
            c.print(f"Name: {plan.spf.name}")
            c.print(f"Value: ", end="")
            c.print(Text(plan.spf.value, no_wrap=True, style="bold green"))
            c.print(f"Purpose: {plan.spf.purpose}")

        if plan.dkim_action:
            c.print("\n[bold cyan]### DKIM Record[/bold cyan]")
            c.print(f"Status: [yellow]Requires email provider action[/yellow]")
            c.print(f"Action: {plan.dkim_action}")

        if not plan.dmarc and not plan.spf and not plan.dkim_action:
            c.print("[green]No DNS changes required — configuration is complete.[/green]")

    def _render_client_explanation(self, text: str) -> None:
        c = self._console
        c.print("\n[bold]## CLIENT EXPLANATION[/bold]")
        c.print(Panel(text, border_style="dim"))

    def _render_implementation_steps(self, phases: list) -> None:
        c = self._console
        c.print("\n[bold]## IMPLEMENTATION STEPS[/bold]")
        if not phases:
            c.print("[green]No implementation steps required.[/green]")
            return

        for phase in phases:
            c.print(f"\n[bold cyan]### Phase {phase.phase}: {phase.title}[/bold cyan]")
            c.print(f"[dim]Timeline: {phase.timeline}[/dim]")
            for step in phase.steps:
                c.print(f"  {step}")
            c.print(f"[dim]Verify: {phase.verification}[/dim]")

    def _render_disclaimers(self) -> None:
        c = self._console
        c.print("\n[bold]## DISCLAIMERS[/bold]")
        c.print(Panel(DISCLAIMERS, border_style="yellow", title="[yellow]Important Notices[/yellow]"))

    # ── Parsed Report Renderer ─────────────────────────────────────────────────

    def render_parsed_report(self, report: ParsedReport) -> None:
        c = self._console
        m = report.metadata
        p = report.policy_published
        s = report.statistics

        c.print()
        c.print(Panel(
            f"[bold]DMARC REPORT: {p.domain.upper()}[/bold]\n"
            f"[dim]{m.org_name}  │  "
            f"{m.begin.strftime('%Y-%m-%d')} – {m.end.strftime('%Y-%m-%d')}  │  "
            f"Report ID: {m.report_id}[/dim]",
            style="bold blue",
            expand=False,
        ))

        # Validation warnings
        warnings = [v for v in report.validation_messages if v.startswith("WARNING")]
        if warnings:
            c.print("\n[bold yellow]⚠  Validation warnings:[/bold yellow]")
            for w in warnings:
                c.print(f"  [yellow]• {w[9:].strip()}[/yellow]")

        # Policy
        policy_color = {"none": "yellow", "quarantine": "blue", "reject": "green"}.get(p.policy, "white")
        c.print(f"\n[bold]Policy published:[/bold] [{policy_color}]p={p.policy}[/{policy_color}]"
                f"  pct={p.pct}  adkim={p.adkim}  aspf={p.aspf}")

        # Statistics table
        c.print("\n[bold]## AUTHENTICATION RESULTS[/bold]")
        stat_table = Table(box=box.SIMPLE, show_header=True, header_style="bold")
        stat_table.add_column("Metric", style="bold", width=22)
        stat_table.add_column("Pass", justify="right", width=14)
        stat_table.add_column("Fail", justify="right", width=14)
        stat_table.add_column("Pass rate", justify="right", width=12)

        def _fmt(n): return f"{n:,}"

        stat_table.add_row(
            "DKIM alignment",
            f"[green]{_fmt(s.dkim_pass)}[/green]",
            f"[red]{_fmt(s.dkim_fail)}[/red]",
            f"{s.pass_rate_dkim}%",
        )
        stat_table.add_row(
            "SPF alignment",
            f"[green]{_fmt(s.spf_pass)}[/green]",
            f"[red]{_fmt(s.spf_fail)}[/red]",
            f"{s.pass_rate_spf}%",
        )
        stat_table.add_row(
            "DMARC overall",
            f"[green]{_fmt(s.fully_aligned + (s.dkim_pass - s.fully_aligned) + (s.spf_pass - s.fully_aligned))}[/green]",
            f"[red]{_fmt(s.fully_failed)}[/red]",
            f"[bold]{s.pass_rate_overall}%[/bold]",
        )
        stat_table.add_row(
            "Total messages",
            f"[bold]{_fmt(s.total_messages)}[/bold]",
            "",
            f"{s.unique_sources} source IP(s)",
        )
        c.print(stat_table)

        # Disposition breakdown (only if non-trivial)
        if s.disposition_quarantine > 0 or s.disposition_reject > 0:
            c.print(
                f"[dim]Disposition — none: {_fmt(s.disposition_none)}  "
                f"quarantine: {_fmt(s.disposition_quarantine)}  "
                f"reject: {_fmt(s.disposition_reject)}[/dim]"
            )

        # Source breakdown
        c.print("\n[bold]## TOP SOURCES[/bold]")
        src_table = Table(box=box.SIMPLE, show_header=True, header_style="bold")
        src_table.add_column("Source IP", width=18)
        src_table.add_column("Messages", justify="right", width=12)
        src_table.add_column("Classification", width=16)
        src_table.add_column("Confidence", width=10)
        src_table.add_column("DMARC pass rate", justify="right", width=16)

        cls_style = {
            "legitimate": "green",
            "forwarding": "yellow",
            "suspicious": "red",
            "unknown": "dim",
        }
        for src in report.source_classifications[:15]:
            style = cls_style.get(src.classification, "white")
            src_table.add_row(
                src.source_ip,
                _fmt(src.message_count),
                f"[{style}]{src.classification}[/{style}]",
                src.confidence,
                f"{src.pass_rate}%",
            )
        c.print(src_table)

        # Recommendations
        c.print("\n[bold]## RECOMMENDATIONS[/bold]")
        if not report.recommendations:
            c.print("[green]No issues detected — authentication is well-configured.[/green]")
        else:
            pri_style = {"high": "red", "medium": "yellow", "low": "blue", "critical": "bold red"}
            for i, rec in enumerate(report.recommendations, 1):
                style = pri_style.get(rec["priority"], "white")
                c.print(f"\n[{style}]{i}. [{rec['priority'].upper()}] {rec['action']}[/{style}]")
                c.print(f"   {rec['reason']}")
                if rec.get("affected_records"):
                    c.print(f"   [dim]Affected messages: {_fmt(rec['affected_records'])}[/dim]")
