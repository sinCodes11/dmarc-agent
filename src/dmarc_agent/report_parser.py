"""DMARC aggregate report XML parser. Handles .xml, .gz, and .zip files."""

import gzip
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from xml.etree import ElementTree as ET

from .exceptions import DmarcParseError
from .models import (
    DkimAuthResult,
    ParsedReport,
    PolicyEvaluated,
    PolicyPublished,
    ReportMetadata,
    ReportRecord,
    ReportStatistics,
    SourceClassification,
    SpfAuthResult,
)

PARSER_VERSION = "1.0"


class ReportParser:
    def parse_file(self, path: str) -> ParsedReport:
        """Parse a DMARC aggregate report from a file path (.xml, .xml.gz, or .zip)."""
        raw_xml = self._load_file(path)
        root = self._parse_xml(raw_xml)
        validation: list = []

        metadata = self._parse_metadata(root, validation)
        policy = self._parse_policy_published(root, validation)
        records = self._parse_records(root, validation)
        stats = self._compute_statistics(records)
        sources = self._classify_sources(records)
        recommendations = self._generate_recommendations(stats, sources, policy)

        return ParsedReport(
            metadata=metadata,
            policy_published=policy,
            records=records,
            statistics=stats,
            source_classifications=sources,
            validation_messages=validation,
            recommendations=recommendations,
        )

    # ── File Loading ──────────────────────────────────────────────────────────

    def _load_file(self, path: str) -> bytes:
        p = Path(path)
        suffix = p.suffix.lower()

        if suffix == ".gz":
            try:
                with gzip.open(path, "rb") as f:
                    return f.read()
            except OSError as e:
                raise DmarcParseError(f"Failed to decompress gzip file: {e}")

        if suffix == ".zip":
            try:
                with zipfile.ZipFile(path, "r") as zf:
                    xml_names = [n for n in zf.namelist() if n.lower().endswith(".xml")]
                    if not xml_names:
                        raise DmarcParseError("No XML file found inside zip archive")
                    return zf.read(xml_names[0])
            except zipfile.BadZipFile as e:
                raise DmarcParseError(f"Invalid zip file: {e}")

        try:
            return p.read_bytes()
        except OSError as e:
            raise DmarcParseError(f"Cannot read file: {e}")

    def _parse_xml(self, raw: bytes) -> ET.Element:
        try:
            return ET.fromstring(raw)
        except ET.ParseError as e:
            raise DmarcParseError(f"Malformed XML: {e}")

    # ── Metadata ──────────────────────────────────────────────────────────────

    def _parse_metadata(self, root: ET.Element, validation: list) -> ReportMetadata:
        meta = root.find("report_metadata")
        if meta is None:
            raise DmarcParseError("Missing required element: report_metadata")

        org_name = _text(meta, "org_name")
        if not org_name:
            validation.append("WARNING: report_metadata/org_name is empty")

        report_id = _text(meta, "report_id")
        if not report_id:
            validation.append("WARNING: report_metadata/report_id is empty")

        date_range = meta.find("date_range")
        if date_range is None:
            raise DmarcParseError("Missing required element: report_metadata/date_range")

        begin = _parse_timestamp(_text(date_range, "begin"), validation, "date_range/begin")
        end = _parse_timestamp(_text(date_range, "end"), validation, "date_range/end")

        now = datetime.now(timezone.utc)
        begin = begin or now
        end = end or now

        if begin >= end:
            validation.append("WARNING: date_range begin is not before end")

        hours = (end - begin).total_seconds() / 3600
        if hours > 7 * 24:
            validation.append(f"WARNING: Report duration {hours:.0f}h exceeds 7 days")

        return ReportMetadata(
            org_name=org_name or "Unknown",
            email=_text(meta, "email"),
            report_id=report_id or "unknown",
            begin=begin,
            end=end,
            extra_contact_info=_text(meta, "extra_contact_info") or None,
        )

    # ── Policy Published ──────────────────────────────────────────────────────

    def _parse_policy_published(self, root: ET.Element, validation: list) -> PolicyPublished:
        pp = root.find("policy_published")
        if pp is None:
            raise DmarcParseError("Missing required element: policy_published")

        policy = _text(pp, "p", "none").lower()
        if policy not in ("none", "quarantine", "reject"):
            validation.append(f"WARNING: Unrecognized policy '{policy}', treating as 'none'")
            policy = "none"

        pct_str = _text(pp, "pct", "100")
        try:
            pct = max(0, min(100, int(pct_str)))
        except ValueError:
            pct = 100
            validation.append(f"WARNING: Invalid pct value '{pct_str}', defaulting to 100")

        if pct < 100:
            validation.append(f"INFO: Policy applies to {pct}% of messages (pct={pct})")

        sp_val = _text(pp, "sp").lower() or None

        return PolicyPublished(
            domain=_text(pp, "domain"),
            adkim=_text(pp, "adkim", "r"),
            aspf=_text(pp, "aspf", "r"),
            policy=policy,
            subdomain_policy=sp_val,
            pct=pct,
        )

    # ── Records ───────────────────────────────────────────────────────────────

    def _parse_records(self, root: ET.Element, validation: list) -> list:
        records = []
        for rec in root.findall("record"):
            parsed = self._parse_single_record(rec, validation)
            if parsed:
                records.append(parsed)
        if not records:
            validation.append("WARNING: No records found in report")
        return records

    def _parse_single_record(self, rec: ET.Element, validation: list):
        row = rec.find("row")
        if row is None:
            validation.append("WARNING: Skipped record missing <row>")
            return None

        source_ip = _text(row, "source_ip")
        if not source_ip:
            validation.append("WARNING: Record has empty source_ip, skipping")
            return None

        count_str = _text(row, "count", "1")
        try:
            count = max(1, int(count_str))
        except ValueError:
            count = 1
            validation.append(f"WARNING: Invalid count '{count_str}' for {source_ip}, using 1")

        pe = row.find("policy_evaluated")
        policy_evaluated = PolicyEvaluated(
            disposition=_text(pe, "disposition", "none") if pe is not None else "none",
            dkim=_text(pe, "dkim", "fail") if pe is not None else "fail",
            spf=_text(pe, "spf", "fail") if pe is not None else "fail",
        )

        identifiers = rec.find("identifiers")
        header_from = _text(identifiers, "header_from") if identifiers is not None else ""
        envelope_from = _text(identifiers, "envelope_from") if identifiers is not None else None

        dkim_auth, spf_auth = self._parse_auth_results(rec)

        return ReportRecord(
            source_ip=source_ip,
            count=count,
            policy_evaluated=policy_evaluated,
            header_from=header_from,
            dkim_auth=dkim_auth,
            spf_auth=spf_auth,
            envelope_from=envelope_from or None,
        )

    def _parse_auth_results(self, rec: ET.Element):
        auth = rec.find("auth_results")
        if auth is None:
            return [], []

        dkim_results = [
            DkimAuthResult(
                domain=_text(d, "domain"),
                result=_text(d, "result", "none").lower(),
                selector=_text(d, "selector") or None,
            )
            for d in auth.findall("dkim")
        ]

        spf_results = [
            SpfAuthResult(
                domain=_text(s, "domain"),
                result=_text(s, "result", "none").lower(),
                scope=_text(s, "scope") or None,
            )
            for s in auth.findall("spf")
        ]

        return dkim_results, spf_results

    # ── Statistics ────────────────────────────────────────────────────────────

    def _compute_statistics(self, records: list) -> ReportStatistics:
        if not records:
            return ReportStatistics(
                total_messages=0, dkim_pass=0, dkim_fail=0,
                spf_pass=0, spf_fail=0, fully_aligned=0, fully_failed=0,
                disposition_none=0, disposition_quarantine=0, disposition_reject=0,
                unique_sources=0, pass_rate_dkim=0.0, pass_rate_spf=0.0,
                pass_rate_overall=0.0,
            )

        def weighted(pred): return sum(r.count for r in records if pred(r))

        total = weighted(lambda r: True)
        dkim_pass = weighted(lambda r: r.policy_evaluated.dkim == "pass")
        spf_pass = weighted(lambda r: r.policy_evaluated.spf == "pass")
        fully_aligned = weighted(lambda r: r.policy_evaluated.dkim == "pass" and r.policy_evaluated.spf == "pass")
        fully_failed = weighted(lambda r: r.policy_evaluated.dkim == "fail" and r.policy_evaluated.spf == "fail")
        dmarc_pass = weighted(lambda r: r.policy_evaluated.dkim == "pass" or r.policy_evaluated.spf == "pass")
        disp_none = weighted(lambda r: r.policy_evaluated.disposition == "none")
        disp_q = weighted(lambda r: r.policy_evaluated.disposition == "quarantine")
        disp_r = weighted(lambda r: r.policy_evaluated.disposition == "reject")

        def pct(n): return round(n / total * 100, 1) if total > 0 else 0.0

        return ReportStatistics(
            total_messages=total,
            dkim_pass=dkim_pass,
            dkim_fail=total - dkim_pass,
            spf_pass=spf_pass,
            spf_fail=total - spf_pass,
            fully_aligned=fully_aligned,
            fully_failed=fully_failed,
            disposition_none=disp_none,
            disposition_quarantine=disp_q,
            disposition_reject=disp_r,
            unique_sources=len({r.source_ip for r in records}),
            pass_rate_dkim=pct(dkim_pass),
            pass_rate_spf=pct(spf_pass),
            pass_rate_overall=pct(dmarc_pass),
        )

    # ── Source Classification ─────────────────────────────────────────────────

    def _classify_sources(self, records: list) -> list:
        by_ip: dict = {}
        for r in records:
            by_ip.setdefault(r.source_ip, []).append(r)

        results = []
        for ip, recs in by_ip.items():
            total = sum(r.count for r in recs)
            dkim_pass = sum(r.count for r in recs if r.policy_evaluated.dkim == "pass")
            spf_pass = sum(r.count for r in recs if r.policy_evaluated.spf == "pass")
            dmarc_pass = sum(
                r.count for r in recs
                if r.policy_evaluated.dkim == "pass" or r.policy_evaluated.spf == "pass"
            )
            pass_rate = round(dmarc_pass / total * 100, 1) if total > 0 else 0.0

            classification, confidence, evidence = _classify_ip(
                total, dkim_pass, spf_pass, dmarc_pass
            )
            results.append(SourceClassification(
                source_ip=ip,
                classification=classification,
                confidence=confidence,
                evidence=evidence,
                message_count=total,
                pass_rate=pass_rate,
            ))

        results.sort(key=lambda c: c.message_count, reverse=True)
        return results

    # ── Recommendations ───────────────────────────────────────────────────────

    def _generate_recommendations(
        self,
        stats: ReportStatistics,
        sources: list,
        policy: PolicyPublished,
    ) -> list:
        recs = []

        suspicious = [s for s in sources if s.classification == "suspicious"]
        if suspicious:
            vol = sum(s.message_count for s in suspicious)
            recs.append({
                "priority": "high",
                "action": "Investigate unauthorized senders",
                "reason": (
                    f"{len(suspicious)} source IP(s) sent {vol} message(s) failing both "
                    "DKIM and SPF — potential spoofing or misconfigured sender"
                ),
                "affected_records": vol,
            })

        if stats.total_messages > 0 and stats.pass_rate_overall < 90.0:
            failures = stats.total_messages - round(stats.pass_rate_overall / 100 * stats.total_messages)
            recs.append({
                "priority": "high",
                "action": "Investigate authentication failures",
                "reason": (
                    f"Overall DMARC pass rate is {stats.pass_rate_overall}% — legitimate senders "
                    "may not be properly configured"
                ),
                "affected_records": failures,
            })

        if policy.policy == "none":
            recs.append({
                "priority": "medium",
                "action": "Progress DMARC policy from p=none to p=quarantine",
                "reason": (
                    "You are in monitoring mode. Review this report and advance to "
                    "p=quarantine after confirming all legitimate senders are authenticated."
                ),
                "affected_records": 0,
            })

        if stats.total_messages > 0 and stats.pass_rate_dkim < 95.0:
            recs.append({
                "priority": "medium",
                "action": "Review DKIM configuration",
                "reason": (
                    f"DKIM pass rate is {stats.pass_rate_dkim}% — some senders may not be "
                    "signing with DKIM or using a selector not in DNS"
                ),
                "affected_records": stats.dkim_fail,
            })

        if stats.total_messages > 0 and stats.pass_rate_spf < 95.0:
            recs.append({
                "priority": "medium",
                "action": "Review SPF record",
                "reason": (
                    f"SPF pass rate is {stats.pass_rate_spf}% — some sending IPs may not "
                    "be included in your SPF record"
                ),
                "affected_records": stats.spf_fail,
            })

        return recs


# ── Module-level helpers ──────────────────────────────────────────────────────

def _text(element: ET.Element, path: str, default: str = "") -> str:
    el = element.find(path)
    return (el.text or "").strip() if el is not None else default


def _parse_timestamp(value: str, validation: list, field: str):
    try:
        return datetime.fromtimestamp(int(value), tz=timezone.utc)
    except (ValueError, TypeError, OSError):
        validation.append(f"WARNING: Invalid timestamp in {field}: '{value}'")
        return None


def _classify_ip(total: int, dkim_pass: int, spf_pass: int, dmarc_pass: int):
    """Return (classification, confidence, evidence) for a source IP."""
    evidence = []

    if dkim_pass == total and spf_pass == total:
        evidence.append("All messages pass both DKIM and SPF alignment")
        return "legitimate", "high", evidence

    if dkim_pass == total and spf_pass == 0:
        evidence.append("DKIM passes but SPF fails — consistent with email forwarding")
        return "forwarding", "medium", evidence

    if dkim_pass == 0 and spf_pass == 0:
        evidence.append("All messages fail both DKIM and SPF alignment")
        return "suspicious", "high", evidence

    if dmarc_pass >= total * 0.8:
        evidence.append(f"Majority of messages pass DMARC ({round(dmarc_pass/total*100)}%)")
        return "legitimate", "medium", evidence

    evidence.append("Mixed pass/fail results — inconsistent authentication")
    return "unknown", "low", evidence
