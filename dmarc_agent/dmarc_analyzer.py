"""DMARC record parser, policy evaluator, and staged rollout record generator."""

from typing import Optional

from .dns_fetcher import DnsFetcher
from .models import DmarcPolicy, DmarcResult, DnsStatus

VALID_POLICIES = {"none", "quarantine", "reject"}


class DmarcAnalyzer:
    def __init__(self, fetcher: DnsFetcher):
        self._fetcher = fetcher

    def analyze(self, domain: str) -> DmarcResult:
        """Fetch and analyze _dmarc.<domain> TXT record."""
        dmarc_domain = f"_dmarc.{domain}"
        response = self._fetcher.query_txt(dmarc_domain)

        if response.status == DnsStatus.NXDOMAIN or not response.records:
            return self._absent_result(domain)

        raw_record = self._find_dmarc_record(response.records)
        if raw_record is None:
            return self._absent_result(domain)

        tags = self._parse_tags(raw_record)

        policy = self._parse_policy(tags.get("p"))
        subdomain_policy = self._parse_policy(tags.get("sp"))
        rua = self._parse_addresses(tags.get("rua", ""))
        ruf = self._parse_addresses(tags.get("ruf", ""))
        fo = tags.get("fo")
        pct = self._parse_pct(tags.get("pct", "100"))
        aspf = tags.get("aspf", "r")
        adkim = tags.get("adkim", "r")

        result = DmarcResult(
            domain=domain,
            present=True,
            raw_record=raw_record,
            policy=policy,
            subdomain_policy=subdomain_policy,
            rua=rua,
            ruf=ruf,
            fo=fo,
            pct=pct,
            aspf=aspf,
            adkim=adkim,
        )

        result.issues = self._evaluate_issues(result)
        result.progression_stage = self._determine_progression_stage(result)
        result.recommended_record = self._generate_recommended_record(domain, result.progression_stage)
        result.risk_contribution = self._assess_risk_contribution(result)

        return result

    # ── Parsing ────────────────────────────────────────────────────────────────

    def _find_dmarc_record(self, records: list) -> Optional[str]:
        for r in records:
            if r.value.strip().lower().startswith("v=dmarc1"):
                return r.value.strip()
        return None

    def _parse_tags(self, record: str) -> dict:
        """Split on ; and extract tag=value pairs."""
        tags = {}
        for part in record.split(";"):
            part = part.strip()
            if not part:
                continue
            if "=" in part:
                key, _, value = part.partition("=")
                tags[key.strip().lower()] = value.strip()
        return tags

    def _parse_policy(self, value: Optional[str]) -> Optional[DmarcPolicy]:
        if not value:
            return None
        value = value.lower().strip()
        mapping = {
            "none": DmarcPolicy.NONE,
            "quarantine": DmarcPolicy.QUARANTINE,
            "reject": DmarcPolicy.REJECT,
        }
        return mapping.get(value)

    def _parse_addresses(self, value: str) -> list:
        """Parse comma-separated mailto: addresses."""
        if not value:
            return []
        result = []
        for addr in value.split(","):
            addr = addr.strip()
            if addr.lower().startswith("mailto:"):
                result.append(addr[7:].strip())
            elif addr:
                result.append(addr)
        return result

    def _parse_pct(self, value: str) -> int:
        try:
            pct = int(value)
            return max(0, min(100, pct))
        except (ValueError, TypeError):
            return 100

    # ── Evaluation ─────────────────────────────────────────────────────────────

    def _evaluate_issues(self, result: DmarcResult) -> list:
        issues = []

        if not result.rua:
            issues.append("No aggregate reporting (rua=) configured — no visibility into email authentication failures")

        if not result.ruf:
            issues.append("No forensic reporting (ruf=) configured — missing per-failure detail reports")

        if result.fo is None or result.fo == "0":
            issues.append("fo=1 recommended — current setting only reports when all mechanisms fail, missing partial failures")

        if result.policy == DmarcPolicy.NONE and not result.rua and not result.ruf:
            issues.append("DMARC p=none with no reporting addresses provides zero protection or visibility")

        if result.policy == DmarcPolicy.REJECT and result.pct < 100:
            issues.append(f"pct={result.pct} with p=reject defeats the purpose — only {result.pct}% of mail is evaluated")

        if result.subdomain_policy is None and result.policy == DmarcPolicy.NONE:
            issues.append("Subdomains inherit p=none — they are also unprotected")

        return issues

    def _determine_progression_stage(self, result: DmarcResult) -> int:
        if not result.present or result.policy is None:
            return 0
        if result.policy == DmarcPolicy.NONE and result.rua:
            return 1
        if result.policy == DmarcPolicy.NONE:
            return 1  # Partial stage 1
        if result.policy == DmarcPolicy.QUARANTINE and result.pct < 100:
            return 2
        if result.policy == DmarcPolicy.QUARANTINE:
            return 3
        if result.policy == DmarcPolicy.REJECT:
            return 4
        return 0

    def _generate_recommended_record(self, domain: str, current_stage: int) -> str:
        """Always generates next-stage record. Never jumps to p=reject as first step."""
        rua = f"mailto:dmarc@{domain}"
        ruf = f"mailto:dmarc@{domain}"
        base = f"rua={rua}; ruf={ruf}; fo=1"

        # Stage 0 or 1 → recommend Stage 1 (p=none, monitoring)
        if current_stage <= 1:
            return f"v=DMARC1; p=none; {base}"

        # Stage 1 → recommend Stage 2 (quarantine, partial)
        if current_stage == 1:
            return f"v=DMARC1; p=quarantine; pct=10; {base}"

        # Stage 2 → recommend Stage 3 (quarantine, full)
        if current_stage == 2:
            return f"v=DMARC1; p=quarantine; {base}"

        # Stage 3 → recommend Stage 4 (reject)
        if current_stage == 3:
            return f"v=DMARC1; p=reject; {base}"

        # Already at reject — maintain
        return f"v=DMARC1; p=reject; {base}"

    def _assess_risk_contribution(self, result: DmarcResult) -> str:
        if not result.present:
            return "high"
        if result.policy == DmarcPolicy.NONE:
            if not result.rua and not result.ruf:
                return "high"
            return "medium"
        if result.policy == DmarcPolicy.QUARANTINE:
            return "low"
        if result.policy == DmarcPolicy.REJECT:
            return "low"
        return "medium"

    def _absent_result(self, domain: str) -> DmarcResult:
        rua = f"mailto:dmarc@{domain}"
        ruf = f"mailto:dmarc@{domain}"
        recommended = f"v=DMARC1; p=none; rua={rua}; ruf={ruf}; fo=1"
        return DmarcResult(
            domain=domain,
            present=False,
            raw_record=None,
            recommended_record=recommended,
            risk_contribution="high",
            progression_stage=0,
            issues=["No DMARC record found — no policy instructs receivers how to handle authentication failures"],
        )
