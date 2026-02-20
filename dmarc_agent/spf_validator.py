"""SPF record parser, lookup counter, misconfiguration detector, and record generator."""

from typing import Optional

from .dns_fetcher import DnsFetcher
from .exceptions import RecursionLimitError, SpfParseError
from .models import (
    DnsStatus,
    SpfLookupBreakdown,
    SpfMechanism,
    SpfMisconfiguration,
    SpfQualifier,
    SpfResult,
)

MAX_LOOKUPS = 10
MAX_RECURSION_DEPTH = 10
LOOKUP_MECHANISMS = {"include", "a", "mx", "ptr", "exists", "redirect"}
ZERO_LOOKUP_MECHANISMS = {"ip4", "ip6", "all"}


class SpfValidator:
    def __init__(self, fetcher: DnsFetcher):
        self._fetcher = fetcher

    def validate(self, domain: str) -> SpfResult:
        """Full SPF validation sequence per spf-validator.md."""
        response = self._fetcher.query_txt(domain)

        if response.status == DnsStatus.NXDOMAIN:
            return self._absent_result(domain, "NXDOMAIN — domain does not exist")

        txt_values = [r.value for r in response.records]
        raw_record, is_duplicate = self._extract_spf_record(txt_values)

        if raw_record is None:
            result = SpfResult(domain=domain, present=False, raw_record=None, duplicate_records=is_duplicate)
            result.misconfigurations = [_no_spf_misconfiguration()]
            result.risk_contribution = "critical"
            return result

        mechanisms = self._parse_mechanisms(raw_record)
        all_qualifier = self._find_all_qualifier(mechanisms)

        try:
            total_lookups, breakdown = self._count_lookups(raw_record)
        except RecursionLimitError:
            total_lookups = MAX_LOOKUPS + 1
            breakdown = []

        if total_lookups > MAX_LOOKUPS:
            lookup_status = "exceeded"
        elif total_lookups >= 8:
            lookup_status = "at_limit"
        else:
            lookup_status = "within_limit"

        misconfigs = self._detect_misconfigurations(mechanisms, total_lookups, is_duplicate)
        recommended = self._generate_recommended_record(mechanisms, misconfigs)
        risk = self._assess_risk_contribution(misconfigs)

        return SpfResult(
            domain=domain,
            present=True,
            raw_record=raw_record,
            mechanisms=mechanisms,
            all_qualifier=all_qualifier,
            total_lookups=total_lookups,
            lookup_limit_status=lookup_status,
            lookup_breakdown=breakdown,
            misconfigurations=misconfigs,
            risk_contribution=risk,
            recommended_record=recommended,
            duplicate_records=is_duplicate,
        )

    # ── Extraction ─────────────────────────────────────────────────────────────

    def _extract_spf_record(self, txt_values: list) -> tuple:
        """Returns (record_string | None, is_duplicate)."""
        spf_records = [v for v in txt_values if v.strip().lower().startswith("v=spf1")]
        if not spf_records:
            return None, False
        return spf_records[0], len(spf_records) > 1

    # ── Parsing ────────────────────────────────────────────────────────────────

    def _parse_mechanisms(self, record: str) -> list:
        """Tokenize SPF record into SpfMechanism list."""
        tokens = record.strip().split()
        mechanisms = []

        for i, token in enumerate(tokens):
            if token.lower() == "v=spf1":
                continue

            # Parse qualifier
            if token and token[0] in "+-~?":
                qualifier_char = token[0]
                rest = token[1:]
            else:
                qualifier_char = "+"
                rest = token

            qualifier = _char_to_qualifier(qualifier_char)

            # Split mechanism type and argument
            if ":" in rest:
                mtype, argument = rest.split(":", 1)
            elif "/" in rest and rest.split("/")[0].lower() in ("a", "mx"):
                # e.g. a/24
                parts = rest.split("/", 1)
                mtype = parts[0]
                argument = "/" + parts[1]
            else:
                mtype = rest
                argument = None

            mtype = mtype.lower()

            mechanisms.append(SpfMechanism(
                order=i,
                raw=token,
                mtype=mtype,
                qualifier=qualifier,
                argument=argument,
            ))

        return mechanisms

    def _find_all_qualifier(self, mechanisms: list) -> Optional[SpfQualifier]:
        for m in mechanisms:
            if m.mtype == "all":
                return m.qualifier
        return None

    # ── Lookup Counting ────────────────────────────────────────────────────────

    def _count_lookups(
        self,
        record: str,
        depth: int = 0,
        seen_domains: Optional[set] = None,
    ) -> tuple:
        """Recursively count DNS lookups. Returns (total, breakdown_list)."""
        if seen_domains is None:
            seen_domains = set()
        if depth > MAX_RECURSION_DEPTH:
            raise RecursionLimitError("SPF include chain exceeded maximum depth")

        tokens = record.strip().split()
        total = 0
        breakdown = []

        for token in tokens:
            if token.lower() == "v=spf1":
                continue

            # Strip qualifier
            if token and token[0] in "+-~?":
                rest = token[1:]
            else:
                rest = token

            # Extract type and argument
            if ":" in rest:
                mtype, argument = rest.split(":", 1)
            else:
                mtype, argument = rest, None

            mtype = mtype.lower()

            if mtype == "include" and argument:
                if argument in seen_domains:
                    raise RecursionLimitError(f"SPF include loop detected: {argument}")
                seen_domains.add(argument)
                direct = 1
                recursive = 0
                chain = []
                # Fetch and recurse
                try:
                    resp = self._fetcher.query_txt(argument)
                    if resp.records:
                        txt_values = [r.value for r in resp.records]
                        included_spf, _ = self._extract_spf_record(txt_values)
                        if included_spf:
                            sub_total, sub_bd = self._count_lookups(
                                included_spf, depth + 1, seen_domains
                            )
                            recursive = sub_total
                            chain = [f"{b.mechanism} ({b.subtotal})" for b in sub_bd]
                except Exception:
                    pass  # Count the include lookup itself even if fetch fails
                bd = SpfLookupBreakdown(
                    mechanism=token,
                    direct_lookups=direct,
                    recursive_lookups=recursive,
                    subtotal=direct + recursive,
                    chain=chain,
                )
                total += direct + recursive
                breakdown.append(bd)

            elif mtype in ("a", "mx", "ptr", "exists"):
                total += 1
                breakdown.append(SpfLookupBreakdown(
                    mechanism=token,
                    direct_lookups=1,
                    recursive_lookups=0,
                    subtotal=1,
                ))

            elif mtype == "redirect" and argument:
                total += 1
                breakdown.append(SpfLookupBreakdown(
                    mechanism=token,
                    direct_lookups=1,
                    recursive_lookups=0,
                    subtotal=1,
                ))

        return total, breakdown

    # ── Misconfiguration Detection ─────────────────────────────────────────────

    def _detect_misconfigurations(
        self, mechanisms: list, total_lookups: int, duplicate: bool
    ) -> list:
        issues = []

        # SPF-CRIT-001: pass-all
        all_mech = next((m for m in mechanisms if m.mtype == "all"), None)
        if all_mech and all_mech.qualifier in (SpfQualifier.PASS, SpfQualifier.NEUTRAL):
            qualifier_display = all_mech.qualifier.value if all_mech.qualifier != SpfQualifier.NEUTRAL else "?"
            issues.append(SpfMisconfiguration(
                id="SPF-CRIT-001",
                name="pass_all",
                severity="critical",
                description=f"SPF uses {qualifier_display}all — allows anyone to send email as this domain",
                remediation="Replace with -all after verifying all legitimate senders are included",
            ))

        # SPF-CRIT-003: lookup exceeded
        if total_lookups > MAX_LOOKUPS:
            issues.append(SpfMisconfiguration(
                id="SPF-CRIT-003",
                name="lookup_exceeded",
                severity="critical",
                description=f"SPF record requires {total_lookups} DNS lookups, exceeding the 10-lookup limit (causes permerror)",
                remediation="Flatten includes — replace include: mechanisms with ip4:/ip6: ranges, or remove unused senders",
            ))

        # SPF-HIGH-001: softfail
        if all_mech and all_mech.qualifier == SpfQualifier.SOFTFAIL:
            issues.append(SpfMisconfiguration(
                id="SPF-HIGH-001",
                name="softfail_all",
                severity="high",
                description="SPF uses ~all (softfail) — spoofed emails pass with a warning flag instead of being rejected",
                remediation="Change to -all after confirming all legitimate senders are in the record",
            ))

        # SPF-HIGH-002: duplicate records
        if duplicate:
            issues.append(SpfMisconfiguration(
                id="SPF-HIGH-002",
                name="duplicate_records",
                severity="high",
                description="Multiple SPF TXT records found — RFC 7208 requires exactly one SPF record",
                remediation="Merge all SPF mechanisms into a single TXT record and remove the others",
            ))

        # SPF-HIGH-003: ptr mechanism
        if any(m.mtype == "ptr" for m in mechanisms):
            issues.append(SpfMisconfiguration(
                id="SPF-HIGH-003",
                name="ptr_mechanism",
                severity="high",
                description="SPF uses the deprecated ptr mechanism — slow, unreliable, and discouraged by RFC 7208",
                remediation="Replace ptr with specific ip4:/ip6: ranges or a: mechanisms",
            ))

        # SPF-MED-001: neutral all
        if all_mech and all_mech.qualifier == SpfQualifier.NEUTRAL:
            issues.append(SpfMisconfiguration(
                id="SPF-MED-001",
                name="neutral_all",
                severity="medium",
                description="SPF uses ?all (neutral) — provides no protection against spoofing",
                remediation="Change to ~all immediately, then -all after validating legitimate senders",
            ))

        # SPF-MED-002: near limit
        if 8 <= total_lookups <= MAX_LOOKUPS:
            issues.append(SpfMisconfiguration(
                id="SPF-MED-002",
                name="near_lookup_limit",
                severity="medium",
                description=f"SPF record uses {total_lookups}/10 DNS lookups — adding more senders may exceed the limit",
                remediation="Consider flattening includes to ip4:/ip6: ranges to create headroom",
            ))

        # SPF-MED-003: redirect + all conflict
        has_redirect = any(m.mtype == "redirect" for m in mechanisms)
        if has_redirect and all_mech:
            issues.append(SpfMisconfiguration(
                id="SPF-MED-003",
                name="redirect_with_all",
                severity="medium",
                description="SPF record has both redirect= modifier and all mechanism — redirect is dead code when all is present",
                remediation="Remove the redirect= modifier or the all mechanism depending on intended behavior",
            ))

        return issues

    # ── Record Generation ──────────────────────────────────────────────────────

    def _generate_recommended_record(self, mechanisms: list, misconfigs: list) -> str:
        """Build a hardened SPF record ordered per spec. Always uses -all."""
        if not mechanisms:
            return "v=spf1 -all"

        ip4s, ip6s, a_mechs, mx_mechs, includes, others = [], [], [], [], [], []

        for m in mechanisms:
            if m.mtype == "all":
                continue  # Will always append -all
            if m.mtype == "redirect":
                continue  # Exclude redirect if all is present (SPF-MED-003)

            # Use the original qualifier unless it's +all situation
            q = m.qualifier.value if m.qualifier != SpfQualifier.PASS else ""
            if m.mtype == "ip4":
                ip4s.append(f"ip4:{m.argument}")
            elif m.mtype == "ip6":
                ip6s.append(f"ip6:{m.argument}")
            elif m.mtype == "a":
                part = f"a:{m.argument}" if m.argument else "a"
                a_mechs.append(part)
            elif m.mtype == "mx":
                part = f"mx:{m.argument}" if m.argument else "mx"
                mx_mechs.append(part)
            elif m.mtype == "include":
                includes.append(f"include:{m.argument}")
            elif m.mtype != "ptr":  # drop deprecated ptr
                raw = m.raw if not m.raw.startswith(m.qualifier.value) else m.raw
                others.append(raw)

        parts = ["v=spf1"]
        parts.extend(ip4s)
        parts.extend(ip6s)
        parts.extend(a_mechs)
        parts.extend(mx_mechs)
        parts.extend(includes)
        parts.extend(others)
        parts.append("-all")

        return " ".join(parts)

    def _assess_risk_contribution(self, misconfigs: list) -> str:
        severities = {m.severity for m in misconfigs}
        if "critical" in severities:
            return "critical"
        if "high" in severities:
            return "high"
        if "medium" in severities:
            return "medium"
        return "low"

    def _absent_result(self, domain: str, reason: str) -> SpfResult:
        result = SpfResult(domain=domain, present=False, raw_record=None)
        result.misconfigurations = [_no_spf_misconfiguration()]
        result.risk_contribution = "critical"
        result.warnings = [reason]
        return result


# ── Helpers ────────────────────────────────────────────────────────────────────

def _char_to_qualifier(char: str) -> SpfQualifier:
    return {
        "+": SpfQualifier.PASS,
        "-": SpfQualifier.FAIL,
        "~": SpfQualifier.SOFTFAIL,
        "?": SpfQualifier.NEUTRAL,
    }.get(char, SpfQualifier.PASS)


def _no_spf_misconfiguration() -> SpfMisconfiguration:
    return SpfMisconfiguration(
        id="SPF-CRIT-002",
        name="no_spf_record",
        severity="critical",
        description="No SPF record found — anyone can send email claiming to be from this domain",
        remediation="Create a TXT record at the root domain: v=spf1 [your-senders] -all",
    )
