"""Unit tests for DkimChecker — selector lookup, valid/revoked/absent key detection."""

from dmarc_agent.dkim_checker import DkimChecker

from .helpers import mock_fetcher, nxdomain

DOMAIN = "example.com"
SELECTOR = "google"
DKIM_DOMAIN = f"{SELECTOR}._domainkey.{DOMAIN}"
VALID_KEY = "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQ=="


class TestDkimNoSelector:
    def test_none_selector_not_checked(self):
        fetcher = mock_fetcher()
        result = DkimChecker(fetcher).check(DOMAIN, None)
        assert not result.checked

    def test_none_selector_not_present(self):
        fetcher = mock_fetcher()
        result = DkimChecker(fetcher).check(DOMAIN, None)
        assert not result.present

    def test_none_selector_makes_no_dns_queries(self):
        fetcher = mock_fetcher()
        DkimChecker(fetcher).check(DOMAIN, None)
        fetcher.query_txt.assert_not_called()

    def test_none_selector_result_has_no_selector_field(self):
        fetcher = mock_fetcher()
        result = DkimChecker(fetcher).check(DOMAIN, None)
        assert result.selector is None


class TestDkimFound:
    def test_valid_key_present_is_true(self):
        fetcher = mock_fetcher({DKIM_DOMAIN: [VALID_KEY]})
        result = DkimChecker(fetcher).check(DOMAIN, SELECTOR)
        assert result.present

    def test_valid_key_checked_is_true(self):
        fetcher = mock_fetcher({DKIM_DOMAIN: [VALID_KEY]})
        result = DkimChecker(fetcher).check(DOMAIN, SELECTOR)
        assert result.checked

    def test_valid_key_risk_is_low(self):
        fetcher = mock_fetcher({DKIM_DOMAIN: [VALID_KEY]})
        result = DkimChecker(fetcher).check(DOMAIN, SELECTOR)
        assert result.risk_contribution == "low"

    def test_valid_key_raw_record_stored(self):
        fetcher = mock_fetcher({DKIM_DOMAIN: [VALID_KEY]})
        result = DkimChecker(fetcher).check(DOMAIN, SELECTOR)
        assert result.raw_record == VALID_KEY

    def test_selector_stored_on_result(self):
        fetcher = mock_fetcher({DKIM_DOMAIN: [VALID_KEY]})
        result = DkimChecker(fetcher).check(DOMAIN, SELECTOR)
        assert result.selector == SELECTOR


class TestDkimNotFound:
    def test_nxdomain_present_is_false(self):
        fetcher = mock_fetcher({DKIM_DOMAIN: nxdomain(DKIM_DOMAIN)})
        result = DkimChecker(fetcher).check(DOMAIN, SELECTOR)
        assert not result.present

    def test_nxdomain_checked_is_true(self):
        fetcher = mock_fetcher({DKIM_DOMAIN: nxdomain(DKIM_DOMAIN)})
        result = DkimChecker(fetcher).check(DOMAIN, SELECTOR)
        assert result.checked

    def test_no_records_present_is_false(self):
        fetcher = mock_fetcher({DKIM_DOMAIN: []})
        result = DkimChecker(fetcher).check(DOMAIN, SELECTOR)
        assert not result.present

    def test_absent_risk_is_high(self):
        fetcher = mock_fetcher({DKIM_DOMAIN: []})
        result = DkimChecker(fetcher).check(DOMAIN, SELECTOR)
        assert result.risk_contribution == "high"

    def test_revoked_key_present_is_false(self):
        # RFC 6376: empty p= means the key has been revoked
        revoked = "v=DKIM1; k=rsa; p="
        fetcher = mock_fetcher({DKIM_DOMAIN: [revoked]})
        result = DkimChecker(fetcher).check(DOMAIN, SELECTOR)
        assert not result.present

    def test_revoked_key_checked_is_true(self):
        revoked = "v=DKIM1; k=rsa; p="
        fetcher = mock_fetcher({DKIM_DOMAIN: [revoked]})
        result = DkimChecker(fetcher).check(DOMAIN, SELECTOR)
        assert result.checked


class TestDkimDomainConstruction:
    def test_dkim_query_uses_correct_domain(self):
        fetcher = mock_fetcher()
        DkimChecker(fetcher).check(DOMAIN, SELECTOR)
        fetcher.query_txt.assert_called_once_with(DKIM_DOMAIN)

    def test_different_selector_builds_different_domain(self):
        fetcher = mock_fetcher()
        DkimChecker(fetcher).check(DOMAIN, "selector1")
        fetcher.query_txt.assert_called_once_with(f"selector1._domainkey.{DOMAIN}")
