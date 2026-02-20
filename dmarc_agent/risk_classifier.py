"""Risk level decision engine. Exact logic from CLAUDE.md risk classification framework."""

from .models import (
    DkimResult,
    DmarcPolicy,
    DmarcResult,
    Issue,
    RiskAssessment,
    RiskLevel,
    SpfQualifier,
    SpfResult,
)


class RiskClassifier:
    def classify(self, spf: SpfResult, dkim: DkimResult, dmarc: DmarcResult) -> RiskAssessment:
        """
        Exact logic from CLAUDE.md:

        IF (no DMARC) OR (SPF +all) OR (no SPF)              → HIGH
        ELIF (DMARC p=none) OR (SPF ~all) OR (no DKIM)       → MEDIUM
        ELIF quarantine/reject AND -all AND DKIM present      → LOW
        ELSE                                                  → MEDIUM
        """
        justification = []
        issues = self._collect_issues(spf, dkim, dmarc)

        if self._is_high(spf, dmarc):
            level = RiskLevel.HIGH
            justification = self._high_reasons(spf, dmarc)
        elif self._is_medium(spf, dkim, dmarc):
            level = RiskLevel.MEDIUM
            justification = self._medium_reasons(spf, dkim, dmarc)
        elif self._is_low(spf, dkim, dmarc):
            level = RiskLevel.LOW
            justification = ["DMARC enforcement active", "SPF hard fail configured", "DKIM confirmed present"]
        else:
            level = RiskLevel.MEDIUM
            justification = ["Configuration partially complete — monitor and progress to full enforcement"]

        return RiskAssessment(level=level, justification=justification, issues=issues)

    # ── Decision Conditions ────────────────────────────────────────────────────

    def _is_high(self, spf: SpfResult, dmarc: DmarcResult) -> bool:
        return (
            not dmarc.present
            or self._spf_has_pass_all(spf)
            or not spf.present
        )

    def _is_medium(self, spf: SpfResult, dkim: DkimResult, dmarc: DmarcResult) -> bool:
        return (
            dmarc.policy == DmarcPolicy.NONE
            or self._spf_has_soft_fail(spf)
            or self._dkim_absent(dkim)
        )

    def _is_low(self, spf: SpfResult, dkim: DkimResult, dmarc: DmarcResult) -> bool:
        return (
            dmarc.policy in (DmarcPolicy.QUARANTINE, DmarcPolicy.REJECT)
            and self._spf_has_hard_fail(spf)
            and dkim.present
        )

    # ── Qualifier Helpers ──────────────────────────────────────────────────────

    def _spf_has_pass_all(self, spf: SpfResult) -> bool:
        if not spf.present:
            return False
        return spf.all_qualifier in (SpfQualifier.PASS, SpfQualifier.NEUTRAL)

    def _spf_has_soft_fail(self, spf: SpfResult) -> bool:
        return spf.present and spf.all_qualifier == SpfQualifier.SOFTFAIL

    def _spf_has_hard_fail(self, spf: SpfResult) -> bool:
        return spf.present and spf.all_qualifier == SpfQualifier.FAIL

    def _dkim_absent(self, dkim: DkimResult) -> bool:
        # Only penalize if DKIM was actually checked and not found
        return dkim.checked and not dkim.present

    # ── Justification Builders ─────────────────────────────────────────────────

    def _high_reasons(self, spf: SpfResult, dmarc: DmarcResult) -> list:
        reasons = []
        if not dmarc.present:
            reasons.append("No DMARC record — receivers have no policy for handling spoofed email")
        if not spf.present:
            reasons.append("No SPF record — anyone can send email claiming to be from this domain")
        if self._spf_has_pass_all(spf):
            reasons.append("SPF uses +all or ?all — authorizes the entire internet to send as this domain")
        return reasons

    def _medium_reasons(self, spf: SpfResult, dkim: DkimResult, dmarc: DmarcResult) -> list:
        reasons = []
        if dmarc.policy == DmarcPolicy.NONE:
            reasons.append("DMARC p=none — collecting data only, spoofed emails not blocked")
        if self._spf_has_soft_fail(spf):
            reasons.append("SPF ~all (softfail) — unauthorized senders pass with a warning, not blocked")
        if self._dkim_absent(dkim):
            reasons.append(f"DKIM selector '{dkim.selector}' not found — email authenticity cannot be cryptographically verified")
        return reasons

    # ── Issue Aggregation ──────────────────────────────────────────────────────

    def _collect_issues(self, spf: SpfResult, dkim: DkimResult, dmarc: DmarcResult) -> list:
        issues = []
        priority = 1

        # DMARC issues (highest priority)
        if not dmarc.present:
            issues.append(Issue(
                id="DMARC-001",
                component="DMARC",
                severity="critical",
                title="No DMARC record",
                description="No DMARC policy found. Receivers have no instructions for handling authentication failures.",
                remediation="Create a DMARC TXT record at _dmarc.[domain] starting with p=none to begin monitoring.",
                priority=priority,
            ))
            priority += 1
        elif dmarc.policy == DmarcPolicy.NONE and not dmarc.rua:
            issues.append(Issue(
                id="DMARC-002",
                component="DMARC",
                severity="high",
                title="DMARC monitoring with no reporting",
                description="DMARC p=none without rua= provides no protection and no visibility.",
                remediation="Add rua=mailto:dmarc@[domain] and ruf=mailto:dmarc@[domain] to the DMARC record.",
                priority=priority,
            ))
            priority += 1
        elif dmarc.policy == DmarcPolicy.NONE:
            issues.append(Issue(
                id="DMARC-003",
                component="DMARC",
                severity="medium",
                title="DMARC in monitoring mode only",
                description="DMARC p=none collects data but does not block spoofed email.",
                remediation="Progress to p=quarantine after 2-4 weeks of reviewing aggregate reports.",
                priority=priority,
            ))
            priority += 1

        # SPF issues
        for mc in spf.misconfigurations:
            sev_map = {"critical": "critical", "high": "high", "medium": "medium", "low": "low"}
            issues.append(Issue(
                id=mc.id,
                component="SPF",
                severity=sev_map.get(mc.severity, "medium"),
                title=mc.name.replace("_", " ").title(),
                description=mc.description,
                remediation=mc.remediation,
                priority=priority,
            ))
            priority += 1

        # DKIM issues
        if dkim.checked and not dkim.present:
            issues.append(Issue(
                id="DKIM-001",
                component="DKIM",
                severity="high",
                title="DKIM not configured",
                description=f"DKIM selector '{dkim.selector}' not found. Email authenticity cannot be cryptographically verified.",
                remediation="Contact your email provider to generate DKIM keys and add the public key DNS record.",
                priority=priority,
            ))
            priority += 1
        elif not dkim.checked:
            issues.append(Issue(
                id="DKIM-002",
                component="DKIM",
                severity="medium",
                title="DKIM status unknown",
                description="No DKIM selector was provided — DKIM presence could not be verified.",
                remediation="Run: dmarc-agent verify-dkim <selector> [domain] to check a specific DKIM selector.",
                priority=priority,
            ))
            priority += 1

        # DMARC reporting
        if dmarc.present and not dmarc.rua:
            issues.append(Issue(
                id="DMARC-004",
                component="DMARC",
                severity="medium",
                title="No aggregate reporting configured",
                description="DMARC aggregate reports (rua=) not configured — no visibility into authentication activity.",
                remediation="Add rua=mailto:dmarc@[domain] to the DMARC record.",
                priority=priority,
            ))
            priority += 1

        return sorted(issues, key=lambda i: i.priority)
