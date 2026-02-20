"""Remediation plan builder: DNS record specs, implementation phases, client explanation."""

from typing import Optional

from .models import (
    DkimResult,
    DmarcPolicy,
    DmarcResult,
    DnsRecordSpec,
    ImplementationPhase,
    RemediationPlan,
    RiskAssessment,
    RiskLevel,
    SpfQualifier,
    SpfResult,
)

DISCLAIMERS = """IMPORTANT NOTICES:

- DNS changes take 15 minutes to 48 hours to fully propagate globally
- Test new SPF records before deploying to avoid blocking legitimate mail
- DMARC reports may take 24-48 hours to begin arriving
- Implement changes during low-volume periods when possible
- Monitor mail flow closely for 72 hours after changes
- Keep backups of current DNS records before making changes
- This analysis is based on DNS state at time of query and may not reflect recent changes

No guarantees are made regarding mail deliverability or security outcomes.
Consult with email administrator or IT provider before production deployment."""


class RecordGenerator:
    def generate(
        self, domain: str, spf: SpfResult, dkim: DkimResult, dmarc: DmarcResult
    ) -> RemediationPlan:
        spf_spec = self._build_spf_spec(spf)
        dmarc_spec = self._build_dmarc_spec(domain, dmarc)
        dkim_action = self._build_dkim_action(dkim)
        phases = self._build_implementation_phases(spf_spec, dmarc_spec, dkim_action, domain, dmarc)

        return RemediationPlan(
            spf=spf_spec,
            dmarc=dmarc_spec,
            dkim_action=dkim_action,
            implementation_phases=phases,
        )

    def generate_client_explanation(self, risk: RiskAssessment, domain: str) -> str:
        """150-word max plain English explanation keyed on risk level."""
        if risk.level == RiskLevel.HIGH:
            return (
                f"Your email security for {domain} has critical gaps that allow attackers to send emails "
                "that appear to come from your domain. This technique — called email spoofing — is used in "
                "phishing attacks targeting your customers and employees.\n\n"
                "The recommended fixes will:\n"
                "- Block spoofed emails from reaching recipients\n"
                "- Provide reports showing who is attempting to impersonate your domain\n"
                "- Improve legitimate email deliverability by proving you are the real sender\n\n"
                "Implementation takes approximately 30 minutes for the initial setup. Full protection "
                "activates progressively over 4-6 weeks as you review reports and tighten the policy."
            )
        if risk.level == RiskLevel.MEDIUM:
            return (
                f"Your email security for {domain} has partial protection in place, but it is not yet "
                "enforced. Spoofed emails may still reach your recipients — they are flagged but not blocked.\n\n"
                "The recommended fixes will:\n"
                "- Move from monitoring mode to active blocking\n"
                "- Ensure your email cryptographic signature is in place\n"
                "- Reduce the window for brand impersonation attacks\n\n"
                "Implementation takes approximately 15-20 minutes. Review your authentication reports "
                "for 2-4 weeks before moving to full enforcement to avoid disrupting legitimate email."
            )
        return (
            f"Your email security for {domain} is well-configured. Active protections are blocking "
            "spoofed emails and your legitimate senders are properly authenticated.\n\n"
            "Ongoing maintenance required:\n"
            "- Review DMARC aggregate reports regularly for new senders\n"
            "- Update your SPF record when adding new email services\n"
            "- Rotate DKIM keys annually with your email provider\n\n"
            "No urgent changes needed. Continue monitoring reports at your configured reporting address."
        )

    # ── Record Specs ───────────────────────────────────────────────────────────

    def _build_spf_spec(self, spf: SpfResult) -> Optional[DnsRecordSpec]:
        """Returns None if SPF is already correctly configured."""
        if (
            spf.present
            and spf.all_qualifier == SpfQualifier.FAIL
            and not spf.misconfigurations
        ):
            return None

        record = spf.recommended_record or "v=spf1 -all"
        if spf.present:
            purpose = "Update existing SPF record — change softfail to hard fail to reject unauthorized senders"
        else:
            purpose = "Create SPF record to define authorized email senders for this domain"

        return DnsRecordSpec(
            record_type="TXT",
            name="@",
            value=record,
            purpose=purpose,
        )

    def _build_dmarc_spec(self, domain: str, dmarc: DmarcResult) -> Optional[DnsRecordSpec]:
        """Returns None if DMARC is already at p=reject with reporting."""
        if (
            dmarc.present
            and dmarc.policy == DmarcPolicy.REJECT
            and dmarc.rua
        ):
            return None

        stage = dmarc.progression_stage + 1
        record = dmarc.recommended_record or f"v=DMARC1; p=none; rua=mailto:dmarc@{domain}; ruf=mailto:dmarc@{domain}; fo=1"

        stage_descriptions = {
            1: "Stage 1 — Monitoring: collect data without affecting mail flow",
            2: "Stage 2 — Partial quarantine: validate legitimate mail flow at 10%",
            3: "Stage 3 — Full quarantine: spoofed email goes to spam",
            4: "Stage 4 — Reject: spoofed email blocked at SMTP level",
        }

        next_actions = {
            1: "Progress to p=quarantine after 2-4 weeks of reviewing aggregate reports",
            2: "Increase to pct=100 after 1-2 weeks of stable mail flow",
            3: "Progress to p=reject after 4-8 weeks of confirmed clean delivery",
            4: "Maintain — review reports regularly, update SPF as senders change",
        }

        next_stage = min(stage, 4)
        return DnsRecordSpec(
            record_type="TXT",
            name="_dmarc",
            value=record,
            purpose=stage_descriptions.get(next_stage, "DMARC deployment"),
            stage=next_stage,
            next_step=next_actions.get(next_stage),
        )

    def _build_dkim_action(self, dkim: DkimResult) -> Optional[str]:
        """Returns plain-text provider instructions. Never a key value."""
        if dkim.present:
            return None
        if not dkim.checked:
            return (
                "DKIM status unknown — contact your email provider (Google Workspace, Microsoft 365, etc.) "
                "to enable DKIM signing. They will generate a key pair and provide a TXT record to add to DNS "
                "at [selector]._domainkey.[domain]."
            )
        return (
            f"DKIM selector '{dkim.selector}' not found for this domain. "
            "Contact your email provider to generate DKIM keys. "
            "They will provide a TXT record to add at [selector]._domainkey.[domain]. "
            "Do not attempt to generate DKIM keys manually — this must be done through your email provider."
        )

    # ── Implementation Phases ──────────────────────────────────────────────────

    def _build_implementation_phases(
        self,
        spf_spec: Optional[DnsRecordSpec],
        dmarc_spec: Optional[DnsRecordSpec],
        dkim_action: Optional[str],
        domain: str,
        dmarc: DmarcResult,
    ) -> list:
        phases = []
        phase_num = 1

        # Phase 1: DMARC deployment (always first if needed)
        if dmarc_spec:
            phases.append(ImplementationPhase(
                phase=phase_num,
                title="DMARC Deployment (Week 1)",
                steps=[
                    "Log into your DNS provider's control panel (Cloudflare, GoDaddy, Namecheap, etc.)",
                    f"Navigate to DNS management for {domain}",
                    "Create a new TXT record:",
                    f"  Name/Host: _dmarc",
                    f"  Value: {dmarc_spec.value}",
                    "  TTL: 3600 (1 hour)",
                    "Save the record",
                    "Wait 15-60 minutes for DNS propagation",
                    f"Verify using: dig TXT _dmarc.{domain}",
                    f"Monitor reports arriving at dmarc@{domain} for 2-4 weeks before proceeding",
                ],
                verification=f"dig TXT _dmarc.{domain}",
                timeline="Week 1 — allow 2-4 weeks of monitoring before advancing",
            ))
            phase_num += 1

        # Phase 2: SPF hardening
        if spf_spec:
            action = "Update existing" if dmarc.present else "Create new"
            phases.append(ImplementationPhase(
                phase=phase_num,
                title="SPF Hardening (Week 2)",
                steps=[
                    f"Review DMARC aggregate reports to confirm all legitimate senders are documented",
                    f"Log into your DNS provider's control panel",
                    f"{action} TXT record at the root domain:",
                    f"  Name/Host: @ (or blank/root)",
                    f"  Value: {spf_spec.value}",
                    "  TTL: 3600 (1 hour)",
                    "Save the record",
                    "Wait 15-60 minutes for DNS propagation",
                    "Send a test email from each mail service you use and confirm delivery",
                    f"Verify using: dig TXT {domain}",
                    "Monitor for 48 hours before proceeding",
                ],
                verification=f"dig TXT {domain}",
                timeline="Week 2 — only after confirming all senders in DMARC reports",
            ))
            phase_num += 1

        # Phase 3: DKIM
        if dkim_action:
            phases.append(ImplementationPhase(
                phase=phase_num,
                title="DKIM Implementation (Week 2-3)",
                steps=[
                    "Contact your email provider support (Google Workspace, Microsoft 365, etc.)",
                    "Request DKIM key generation for this domain",
                    "Provider will give you a TXT record to add to DNS",
                    "Add the record at [selector]._domainkey.[domain] exactly as provided",
                    "Confirm with your provider that DKIM signing is active for outbound mail",
                    "Verify DKIM pass rate in DMARC aggregate reports over the next week",
                ],
                verification=f"dig TXT [selector]._domainkey.{domain}",
                timeline="Week 2-3 — coordinate with email provider, may take 1-2 business days",
            ))
            phase_num += 1

        # Phase 4: DMARC enforcement progression
        if dmarc_spec and dmarc_spec.stage and dmarc_spec.stage < 4:
            rua = f"mailto:dmarc@{domain}"
            ruf = f"mailto:dmarc@{domain}"
            phases.append(ImplementationPhase(
                phase=phase_num,
                title="DMARC Enforcement Progression (Week 4-6+)",
                steps=[
                    f"Review 2-4 weeks of DMARC aggregate reports — confirm all legitimate mail is passing",
                    "Update DMARC to quarantine (partial):",
                    f"  Value: v=DMARC1; p=quarantine; pct=10; rua={rua}; ruf={ruf}; fo=1",
                    "Monitor for 1-2 weeks",
                    "Update to full quarantine:",
                    f"  Value: v=DMARC1; p=quarantine; rua={rua}; ruf={ruf}; fo=1",
                    "Monitor for 4-8 weeks",
                    "Final update to reject (maximum protection):",
                    f"  Value: v=DMARC1; p=reject; rua={rua}; ruf={ruf}; fo=1",
                ],
                verification=f"dig TXT _dmarc.{domain}",
                timeline="Week 4-6 — do not rush, each stage requires validation",
            ))

        return phases
