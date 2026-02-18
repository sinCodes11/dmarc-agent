"""Shared test factories for mock DNS responses and model objects."""

from unittest.mock import MagicMock

from dmarc_agent.models import (
    DkimResult,
    DmarcPolicy,
    DmarcResult,
    DnsRecord,
    DnsResponse,
    DnsStatus,
    SpfQualifier,
    SpfResult,
)


def dns_response(domain, txt_values=None, status=DnsStatus.NOERROR):
    """Build a DnsResponse with zero or more TXT records."""
    records = []
    if txt_values:
        records = [DnsRecord(record_type="TXT", value=v, ttl=3600) for v in txt_values]
    return DnsResponse(domain=domain, record_type="TXT", status=status, records=records)


def nxdomain(domain):
    """Return an NXDOMAIN response for a domain."""
    return dns_response(domain, status=DnsStatus.NXDOMAIN)


def mock_fetcher(mapping=None):
    """
    Build a mock DnsFetcher whose query_txt() returns responses from `mapping`.

    mapping: dict of domain -> list[str] of TXT values, or a DnsResponse.
    Unknown domains return an empty NOERROR response.
    """
    mapping = mapping or {}
    fetcher = MagicMock()

    def _query_txt(domain):
        if domain not in mapping:
            return dns_response(domain)
        val = mapping[domain]
        if isinstance(val, DnsResponse):
            return val
        return dns_response(domain, val)

    fetcher.query_txt.side_effect = _query_txt
    return fetcher


# ── Model object factories ──────────────────────────────────────────────────────

def spf_result(
    domain="example.com",
    present=True,
    all_qualifier=SpfQualifier.FAIL,
    misconfigurations=None,
    raw_record=None,
):
    return SpfResult(
        domain=domain,
        present=present,
        raw_record=raw_record or ("v=spf1 -all" if present else None),
        all_qualifier=all_qualifier if present else None,
        misconfigurations=misconfigurations or [],
    )


def dkim_result(
    domain="example.com",
    selector="default",
    checked=True,
    present=True,
):
    return DkimResult(
        domain=domain,
        selector=selector if checked else None,
        checked=checked,
        present=present,
        raw_record="v=DKIM1; p=MIGfMA0GCSqGSIb3" if present else None,
    )


def dmarc_result(
    domain="example.com",
    present=True,
    policy=DmarcPolicy.REJECT,
    rua=None,
    ruf=None,
    pct=100,
    progression_stage=None,
    recommended_record=None,
):
    if not present:
        return DmarcResult(domain=domain, present=False, raw_record=None)
    _stage = progression_stage if progression_stage is not None else (
        4 if policy == DmarcPolicy.REJECT else
        3 if policy == DmarcPolicy.QUARANTINE else
        1
    )
    return DmarcResult(
        domain=domain,
        present=True,
        raw_record="v=DMARC1; p=reject",
        policy=policy,
        rua=rua if rua is not None else ["dmarc@example.com"],
        ruf=ruf if ruf is not None else ["dmarc@example.com"],
        pct=pct,
        progression_stage=_stage,
        recommended_record=recommended_record,
    )
