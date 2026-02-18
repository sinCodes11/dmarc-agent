"""Unit tests for SpfValidator — covers all detection and generation logic."""

import pytest

from dmarc_agent.models import DnsStatus, SpfQualifier
from dmarc_agent.spf_validator import SpfValidator

from .helpers import dns_response, mock_fetcher, nxdomain

DOMAIN = "example.com"


class TestSpfAbsent:
    def test_no_spf_present_is_false(self):
        fetcher = mock_fetcher({DOMAIN: []})
        result = SpfValidator(fetcher).validate(DOMAIN)
        assert not result.present

    def test_no_spf_has_crit_002(self):
        fetcher = mock_fetcher({DOMAIN: []})
        result = SpfValidator(fetcher).validate(DOMAIN)
        assert any(m.id == "SPF-CRIT-002" for m in result.misconfigurations)

    def test_no_spf_risk_is_critical(self):
        fetcher = mock_fetcher({DOMAIN: []})
        result = SpfValidator(fetcher).validate(DOMAIN)
        assert result.risk_contribution == "critical"

    def test_nxdomain_present_is_false(self):
        fetcher = mock_fetcher({DOMAIN: nxdomain(DOMAIN)})
        result = SpfValidator(fetcher).validate(DOMAIN)
        assert not result.present

    def test_nxdomain_risk_is_critical(self):
        fetcher = mock_fetcher({DOMAIN: nxdomain(DOMAIN)})
        result = SpfValidator(fetcher).validate(DOMAIN)
        assert result.risk_contribution == "critical"

    def test_non_spf_txt_records_treated_as_absent(self):
        fetcher = mock_fetcher({DOMAIN: ["v=something-else"]})
        result = SpfValidator(fetcher).validate(DOMAIN)
        assert not result.present


class TestSpfPresent:
    def test_valid_record_present_is_true(self):
        fetcher = mock_fetcher({DOMAIN: ["v=spf1 include:_spf.google.com -all"]})
        result = SpfValidator(fetcher).validate(DOMAIN)
        assert result.present

    def test_raw_record_preserved(self):
        record = "v=spf1 include:_spf.google.com -all"
        fetcher = mock_fetcher({DOMAIN: [record]})
        result = SpfValidator(fetcher).validate(DOMAIN)
        assert result.raw_record == record


class TestSpfQualifiers:
    def test_hard_fail_qualifier_correct(self):
        fetcher = mock_fetcher({DOMAIN: ["v=spf1 include:_spf.google.com -all"]})
        result = SpfValidator(fetcher).validate(DOMAIN)
        assert result.all_qualifier == SpfQualifier.FAIL

    def test_hard_fail_no_softfail_misconfiguration(self):
        fetcher = mock_fetcher({DOMAIN: ["v=spf1 include:_spf.google.com -all"]})
        result = SpfValidator(fetcher).validate(DOMAIN)
        assert not any(m.id == "SPF-HIGH-001" for m in result.misconfigurations)

    def test_softfail_qualifier_correct(self):
        fetcher = mock_fetcher({DOMAIN: ["v=spf1 include:_spf.google.com ~all"]})
        result = SpfValidator(fetcher).validate(DOMAIN)
        assert result.all_qualifier == SpfQualifier.SOFTFAIL

    def test_softfail_flagged_as_high_001(self):
        fetcher = mock_fetcher({DOMAIN: ["v=spf1 include:_spf.google.com ~all"]})
        result = SpfValidator(fetcher).validate(DOMAIN)
        assert any(m.id == "SPF-HIGH-001" for m in result.misconfigurations)

    def test_pass_all_qualifier_correct(self):
        fetcher = mock_fetcher({DOMAIN: ["v=spf1 +all"]})
        result = SpfValidator(fetcher).validate(DOMAIN)
        assert result.all_qualifier == SpfQualifier.PASS

    def test_pass_all_flagged_as_crit_001(self):
        fetcher = mock_fetcher({DOMAIN: ["v=spf1 +all"]})
        result = SpfValidator(fetcher).validate(DOMAIN)
        assert any(m.id == "SPF-CRIT-001" for m in result.misconfigurations)

    def test_neutral_all_flagged_as_crit_001(self):
        fetcher = mock_fetcher({DOMAIN: ["v=spf1 ?all"]})
        result = SpfValidator(fetcher).validate(DOMAIN)
        assert any(m.id == "SPF-CRIT-001" for m in result.misconfigurations)

    def test_neutral_all_also_flagged_as_med_001(self):
        fetcher = mock_fetcher({DOMAIN: ["v=spf1 ?all"]})
        result = SpfValidator(fetcher).validate(DOMAIN)
        assert any(m.id == "SPF-MED-001" for m in result.misconfigurations)

    def test_implicit_pass_qualifier_on_include(self):
        fetcher = mock_fetcher({DOMAIN: ["v=spf1 include:_spf.google.com -all"]})
        result = SpfValidator(fetcher).validate(DOMAIN)
        include_mech = next(m for m in result.mechanisms if m.mtype == "include")
        assert include_mech.qualifier == SpfQualifier.PASS

    def test_explicit_minus_qualifier_on_include(self):
        fetcher = mock_fetcher({DOMAIN: ["v=spf1 -include:untrusted.com -all"]})
        result = SpfValidator(fetcher).validate(DOMAIN)
        include_mech = next(m for m in result.mechanisms if m.mtype == "include")
        assert include_mech.qualifier == SpfQualifier.FAIL


class TestSpfMisconfigurations:
    def test_duplicate_records_flagged(self):
        fetcher = mock_fetcher({DOMAIN: [
            "v=spf1 include:a.example.com -all",
            "v=spf1 include:b.example.com -all",
        ]})
        result = SpfValidator(fetcher).validate(DOMAIN)
        assert result.duplicate_records
        assert any(m.id == "SPF-HIGH-002" for m in result.misconfigurations)

    def test_single_record_not_duplicate(self):
        fetcher = mock_fetcher({DOMAIN: ["v=spf1 -all"]})
        result = SpfValidator(fetcher).validate(DOMAIN)
        assert not result.duplicate_records

    def test_ptr_mechanism_flagged(self):
        fetcher = mock_fetcher({DOMAIN: ["v=spf1 ptr -all"]})
        result = SpfValidator(fetcher).validate(DOMAIN)
        assert any(m.id == "SPF-HIGH-003" for m in result.misconfigurations)

    def test_hard_fail_clean_has_no_misconfigs(self):
        fetcher = mock_fetcher({DOMAIN: ["v=spf1 ip4:1.2.3.4 -all"]})
        result = SpfValidator(fetcher).validate(DOMAIN)
        assert result.misconfigurations == []

    def test_risk_contribution_critical_for_pass_all(self):
        fetcher = mock_fetcher({DOMAIN: ["v=spf1 +all"]})
        result = SpfValidator(fetcher).validate(DOMAIN)
        assert result.risk_contribution == "critical"

    def test_risk_contribution_high_for_softfail(self):
        fetcher = mock_fetcher({DOMAIN: ["v=spf1 ~all"]})
        result = SpfValidator(fetcher).validate(DOMAIN)
        assert result.risk_contribution == "high"

    def test_risk_contribution_low_for_clean_record(self):
        fetcher = mock_fetcher({DOMAIN: ["v=spf1 ip4:1.2.3.4 -all"]})
        result = SpfValidator(fetcher).validate(DOMAIN)
        assert result.risk_contribution == "low"


class TestSpfLookupCounting:
    def _fetcher_with_n_includes(self, n):
        """Build a fetcher with n includes; each included domain returns no SPF."""
        record = "v=spf1 " + " ".join(f"include:s{i}.example.com" for i in range(n)) + " -all"
        return mock_fetcher({DOMAIN: [record]})

    def test_single_include_counts_as_one(self):
        fetcher = mock_fetcher({DOMAIN: ["v=spf1 include:_spf.google.com -all"]})
        result = SpfValidator(fetcher).validate(DOMAIN)
        assert result.total_lookups == 1
        assert result.lookup_limit_status == "within_limit"

    def test_a_and_mx_each_count_as_one(self):
        fetcher = mock_fetcher({DOMAIN: ["v=spf1 a mx -all"]})
        result = SpfValidator(fetcher).validate(DOMAIN)
        assert result.total_lookups == 2

    def test_ip4_does_not_count_as_lookup(self):
        fetcher = mock_fetcher({DOMAIN: ["v=spf1 ip4:1.2.3.4 ip6:2001:db8::/32 -all"]})
        result = SpfValidator(fetcher).validate(DOMAIN)
        assert result.total_lookups == 0

    def test_zero_lookups_status_is_within_limit(self):
        fetcher = mock_fetcher({DOMAIN: ["v=spf1 ip4:1.2.3.4 -all"]})
        result = SpfValidator(fetcher).validate(DOMAIN)
        assert result.lookup_limit_status == "within_limit"

    def test_near_limit_8_triggers_med_002(self):
        fetcher = self._fetcher_with_n_includes(8)
        result = SpfValidator(fetcher).validate(DOMAIN)
        assert result.total_lookups == 8
        assert result.lookup_limit_status == "at_limit"
        assert any(m.id == "SPF-MED-002" for m in result.misconfigurations)

    def test_exceeded_11_triggers_crit_003(self):
        fetcher = self._fetcher_with_n_includes(11)
        result = SpfValidator(fetcher).validate(DOMAIN)
        assert result.total_lookups == 11
        assert result.lookup_limit_status == "exceeded"
        assert any(m.id == "SPF-CRIT-003" for m in result.misconfigurations)

    def test_recursive_includes_counted(self):
        """An include whose SPF in turn has an include counts both lookups."""
        fetcher = mock_fetcher({
            DOMAIN: ["v=spf1 include:nested.example.com -all"],
            "nested.example.com": ["v=spf1 include:leaf.example.com -all"],
        })
        result = SpfValidator(fetcher).validate(DOMAIN)
        assert result.total_lookups == 2


class TestSpfRecommendedRecord:
    def test_always_ends_with_hard_fail(self):
        fetcher = mock_fetcher({DOMAIN: ["v=spf1 include:_spf.google.com ~all"]})
        result = SpfValidator(fetcher).validate(DOMAIN)
        assert result.recommended_record.endswith("-all")

    def test_ptr_dropped_from_recommended(self):
        fetcher = mock_fetcher({DOMAIN: ["v=spf1 ptr -all"]})
        result = SpfValidator(fetcher).validate(DOMAIN)
        assert "ptr" not in result.recommended_record

    def test_ip4_before_includes_in_recommended(self):
        fetcher = mock_fetcher({DOMAIN: ["v=spf1 include:mail.com ip4:1.2.3.4 -all"]})
        result = SpfValidator(fetcher).validate(DOMAIN)
        rec = result.recommended_record
        assert rec.index("ip4:") < rec.index("include:")

    def test_minimal_hard_fail_record_preserved(self):
        fetcher = mock_fetcher({DOMAIN: ["v=spf1 -all"]})
        result = SpfValidator(fetcher).validate(DOMAIN)
        assert result.recommended_record == "v=spf1 -all"

    def test_includes_preserved_in_recommended(self):
        fetcher = mock_fetcher({DOMAIN: ["v=spf1 include:_spf.google.com ~all"]})
        result = SpfValidator(fetcher).validate(DOMAIN)
        assert "include:_spf.google.com" in result.recommended_record
