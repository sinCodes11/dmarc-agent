"""DKIM presence checker. Only checks explicit selectors. Never guesses or generates keys."""

from typing import Optional

from .dns_fetcher import DnsFetcher
from .models import DkimResult, DnsStatus


class DkimChecker:
    def __init__(self, fetcher: DnsFetcher):
        self._fetcher = fetcher

    def check(self, domain: str, selector: Optional[str]) -> DkimResult:
        """
        If selector is None: returns unchecked result immediately.
        If selector provided: queries <selector>._domainkey.<domain> TXT.
        Never guesses selectors. Never generates key values.
        """
        if selector is None:
            return DkimResult(
                domain=domain,
                selector=None,
                checked=False,
                present=False,
                raw_record=None,
                risk_contribution="medium",  # unknown — treat conservatively
            )

        dkim_domain = self._build_dkim_domain(selector, domain)
        response = self._fetcher.query_txt(dkim_domain)

        if response.status == DnsStatus.NXDOMAIN or not response.records:
            return DkimResult(
                domain=domain,
                selector=selector,
                checked=True,
                present=False,
                raw_record=None,
                risk_contribution="high",
            )

        # Check for a valid DKIM record
        for record in response.records:
            if self._is_valid_dkim_record(record.value):
                return DkimResult(
                    domain=domain,
                    selector=selector,
                    checked=True,
                    present=True,
                    raw_record=record.value,
                    risk_contribution="low",
                )
            # Empty p= means revoked key
            if "p=" in record.value.lower():
                return DkimResult(
                    domain=domain,
                    selector=selector,
                    checked=True,
                    present=False,
                    raw_record=record.value,
                    risk_contribution="high",
                )

        return DkimResult(
            domain=domain,
            selector=selector,
            checked=True,
            present=False,
            raw_record=None,
            risk_contribution="high",
        )

    @staticmethod
    def _build_dkim_domain(selector: str, domain: str) -> str:
        return f"{selector}._domainkey.{domain}"

    @staticmethod
    def _is_valid_dkim_record(txt_value: str) -> bool:
        """True if record contains p= with a non-empty public key value."""
        lower = txt_value.lower()
        if "p=" not in lower:
            return False
        # Find p= and check it has a value
        idx = lower.index("p=")
        remainder = txt_value[idx + 2:]
        # Strip until next tag separator
        key_value = remainder.split(";")[0].strip()
        return len(key_value) > 0
