"""Unit tests for DmarcAnalyzer — parsing, progression stages, risk contribution."""

from dmarc_agent.dmarc_analyzer import DmarcAnalyzer
from dmarc_agent.models import DmarcPolicy

from .helpers import mock_fetcher, nxdomain

DOMAIN = "example.com"
DMARC_DOMAIN = "_dmarc.example.com"


class TestDmarcAbsent:
    def test_no_record_present_is_false(self):
        fetcher = mock_fetcher({DMARC_DOMAIN: []})
        result = DmarcAnalyzer(fetcher).analyze(DOMAIN)
        assert not result.present

    def test_no_record_risk_is_high(self):
        fetcher = mock_fetcher({DMARC_DOMAIN: []})
        result = DmarcAnalyzer(fetcher).analyze(DOMAIN)
        assert result.risk_contribution == "high"

    def test_no_record_stage_is_zero(self):
        fetcher = mock_fetcher({DMARC_DOMAIN: []})
        result = DmarcAnalyzer(fetcher).analyze(DOMAIN)
        assert result.progression_stage == 0

    def test_no_record_recommended_contains_p_none(self):
        fetcher = mock_fetcher({DMARC_DOMAIN: []})
        result = DmarcAnalyzer(fetcher).analyze(DOMAIN)
        assert "p=none" in result.recommended_record

    def test_no_record_has_issue(self):
        fetcher = mock_fetcher({DMARC_DOMAIN: []})
        result = DmarcAnalyzer(fetcher).analyze(DOMAIN)
        assert len(result.issues) > 0

    def test_nxdomain_treated_as_absent(self):
        fetcher = mock_fetcher({DMARC_DOMAIN: nxdomain(DMARC_DOMAIN)})
        result = DmarcAnalyzer(fetcher).analyze(DOMAIN)
        assert not result.present

    def test_non_dmarc_txt_treated_as_absent(self):
        fetcher = mock_fetcher({DMARC_DOMAIN: ["v=something-else"]})
        result = DmarcAnalyzer(fetcher).analyze(DOMAIN)
        assert not result.present


class TestDmarcPolicies:
    def test_policy_none_parsed(self):
        record = "v=DMARC1; p=none; rua=mailto:dmarc@example.com; fo=1"
        fetcher = mock_fetcher({DMARC_DOMAIN: [record]})
        result = DmarcAnalyzer(fetcher).analyze(DOMAIN)
        assert result.policy == DmarcPolicy.NONE

    def test_policy_quarantine_parsed(self):
        record = "v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com"
        fetcher = mock_fetcher({DMARC_DOMAIN: [record]})
        result = DmarcAnalyzer(fetcher).analyze(DOMAIN)
        assert result.policy == DmarcPolicy.QUARANTINE

    def test_policy_reject_parsed(self):
        record = "v=DMARC1; p=reject; rua=mailto:dmarc@example.com"
        fetcher = mock_fetcher({DMARC_DOMAIN: [record]})
        result = DmarcAnalyzer(fetcher).analyze(DOMAIN)
        assert result.policy == DmarcPolicy.REJECT

    def test_present_is_true_for_valid_record(self):
        record = "v=DMARC1; p=none; rua=mailto:dmarc@example.com"
        fetcher = mock_fetcher({DMARC_DOMAIN: [record]})
        result = DmarcAnalyzer(fetcher).analyze(DOMAIN)
        assert result.present


class TestDmarcTagParsing:
    def test_rua_mailto_prefix_stripped(self):
        record = "v=DMARC1; p=none; rua=mailto:reports@example.com"
        fetcher = mock_fetcher({DMARC_DOMAIN: [record]})
        result = DmarcAnalyzer(fetcher).analyze(DOMAIN)
        assert "reports@example.com" in result.rua

    def test_ruf_mailto_prefix_stripped(self):
        record = "v=DMARC1; p=none; rua=mailto:a@example.com; ruf=mailto:b@example.com"
        fetcher = mock_fetcher({DMARC_DOMAIN: [record]})
        result = DmarcAnalyzer(fetcher).analyze(DOMAIN)
        assert "b@example.com" in result.ruf

    def test_multiple_rua_addresses_parsed(self):
        record = "v=DMARC1; p=none; rua=mailto:a@example.com,mailto:b@example.com"
        fetcher = mock_fetcher({DMARC_DOMAIN: [record]})
        result = DmarcAnalyzer(fetcher).analyze(DOMAIN)
        assert len(result.rua) == 2

    def test_pct_value_parsed(self):
        record = "v=DMARC1; p=quarantine; pct=10; rua=mailto:r@example.com"
        fetcher = mock_fetcher({DMARC_DOMAIN: [record]})
        result = DmarcAnalyzer(fetcher).analyze(DOMAIN)
        assert result.pct == 10

    def test_pct_clamped_to_100_when_over(self):
        record = "v=DMARC1; p=quarantine; pct=150; rua=mailto:r@example.com"
        fetcher = mock_fetcher({DMARC_DOMAIN: [record]})
        result = DmarcAnalyzer(fetcher).analyze(DOMAIN)
        assert result.pct == 100

    def test_pct_clamped_to_0_when_negative(self):
        record = "v=DMARC1; p=quarantine; pct=-5; rua=mailto:r@example.com"
        fetcher = mock_fetcher({DMARC_DOMAIN: [record]})
        result = DmarcAnalyzer(fetcher).analyze(DOMAIN)
        assert result.pct == 0

    def test_pct_defaults_to_100_when_absent(self):
        record = "v=DMARC1; p=reject; rua=mailto:r@example.com"
        fetcher = mock_fetcher({DMARC_DOMAIN: [record]})
        result = DmarcAnalyzer(fetcher).analyze(DOMAIN)
        assert result.pct == 100

    def test_aspf_default_is_r(self):
        record = "v=DMARC1; p=reject; rua=mailto:r@example.com"
        fetcher = mock_fetcher({DMARC_DOMAIN: [record]})
        result = DmarcAnalyzer(fetcher).analyze(DOMAIN)
        assert result.aspf == "r"

    def test_adkim_parsed_when_present(self):
        record = "v=DMARC1; p=reject; adkim=s; rua=mailto:r@example.com"
        fetcher = mock_fetcher({DMARC_DOMAIN: [record]})
        result = DmarcAnalyzer(fetcher).analyze(DOMAIN)
        assert result.adkim == "s"


class TestDmarcProgressionStage:
    def test_stage_1_for_none_with_rua(self):
        record = "v=DMARC1; p=none; rua=mailto:r@example.com"
        fetcher = mock_fetcher({DMARC_DOMAIN: [record]})
        result = DmarcAnalyzer(fetcher).analyze(DOMAIN)
        assert result.progression_stage == 1

    def test_stage_1_for_none_without_rua(self):
        record = "v=DMARC1; p=none"
        fetcher = mock_fetcher({DMARC_DOMAIN: [record]})
        result = DmarcAnalyzer(fetcher).analyze(DOMAIN)
        assert result.progression_stage == 1

    def test_stage_2_for_quarantine_partial(self):
        record = "v=DMARC1; p=quarantine; pct=10; rua=mailto:r@example.com"
        fetcher = mock_fetcher({DMARC_DOMAIN: [record]})
        result = DmarcAnalyzer(fetcher).analyze(DOMAIN)
        assert result.progression_stage == 2

    def test_stage_3_for_quarantine_full(self):
        record = "v=DMARC1; p=quarantine; rua=mailto:r@example.com"
        fetcher = mock_fetcher({DMARC_DOMAIN: [record]})
        result = DmarcAnalyzer(fetcher).analyze(DOMAIN)
        assert result.progression_stage == 3

    def test_stage_4_for_reject(self):
        record = "v=DMARC1; p=reject; rua=mailto:r@example.com"
        fetcher = mock_fetcher({DMARC_DOMAIN: [record]})
        result = DmarcAnalyzer(fetcher).analyze(DOMAIN)
        assert result.progression_stage == 4


class TestDmarcIssues:
    def test_missing_rua_flagged_in_issues(self):
        record = "v=DMARC1; p=none"
        fetcher = mock_fetcher({DMARC_DOMAIN: [record]})
        result = DmarcAnalyzer(fetcher).analyze(DOMAIN)
        assert any("rua" in issue.lower() for issue in result.issues)

    def test_missing_ruf_flagged_in_issues(self):
        record = "v=DMARC1; p=none; rua=mailto:r@example.com"
        fetcher = mock_fetcher({DMARC_DOMAIN: [record]})
        result = DmarcAnalyzer(fetcher).analyze(DOMAIN)
        assert any("ruf" in issue.lower() for issue in result.issues)

    def test_reject_with_low_pct_flagged(self):
        record = "v=DMARC1; p=reject; pct=50; rua=mailto:r@example.com"
        fetcher = mock_fetcher({DMARC_DOMAIN: [record]})
        result = DmarcAnalyzer(fetcher).analyze(DOMAIN)
        assert any("pct" in issue for issue in result.issues)

    def test_no_issues_for_well_configured_record(self):
        record = "v=DMARC1; p=reject; rua=mailto:r@example.com; ruf=mailto:r@example.com; fo=1"
        fetcher = mock_fetcher({DMARC_DOMAIN: [record]})
        result = DmarcAnalyzer(fetcher).analyze(DOMAIN)
        assert result.issues == []


class TestDmarcRiskContribution:
    def test_absent_is_high(self):
        fetcher = mock_fetcher({DMARC_DOMAIN: []})
        result = DmarcAnalyzer(fetcher).analyze(DOMAIN)
        assert result.risk_contribution == "high"

    def test_none_without_rua_is_high(self):
        record = "v=DMARC1; p=none"
        fetcher = mock_fetcher({DMARC_DOMAIN: [record]})
        result = DmarcAnalyzer(fetcher).analyze(DOMAIN)
        assert result.risk_contribution == "high"

    def test_none_with_rua_is_medium(self):
        record = "v=DMARC1; p=none; rua=mailto:r@example.com"
        fetcher = mock_fetcher({DMARC_DOMAIN: [record]})
        result = DmarcAnalyzer(fetcher).analyze(DOMAIN)
        assert result.risk_contribution == "medium"

    def test_quarantine_is_low(self):
        record = "v=DMARC1; p=quarantine; rua=mailto:r@example.com"
        fetcher = mock_fetcher({DMARC_DOMAIN: [record]})
        result = DmarcAnalyzer(fetcher).analyze(DOMAIN)
        assert result.risk_contribution == "low"

    def test_reject_is_low(self):
        record = "v=DMARC1; p=reject; rua=mailto:r@example.com"
        fetcher = mock_fetcher({DMARC_DOMAIN: [record]})
        result = DmarcAnalyzer(fetcher).analyze(DOMAIN)
        assert result.risk_contribution == "low"
