"""Unit tests for RiskClassifier — HIGH/MEDIUM/LOW logic from CLAUDE.md."""

from dmarc_agent.models import DmarcPolicy, RiskLevel, SpfQualifier
from dmarc_agent.risk_classifier import RiskClassifier

from .helpers import dkim_result, dmarc_result, spf_result


def classify(spf=None, dkim=None, dmarc=None):
    s = spf or spf_result()
    d = dkim or dkim_result()
    r = dmarc or dmarc_result()
    return RiskClassifier().classify(s, d, r)


class TestHighRisk:
    def test_no_dmarc_is_high(self):
        result = classify(dmarc=dmarc_result(present=False))
        assert result.level == RiskLevel.HIGH

    def test_no_spf_is_high(self):
        result = classify(spf=spf_result(present=False))
        assert result.level == RiskLevel.HIGH

    def test_spf_pass_all_is_high(self):
        result = classify(spf=spf_result(all_qualifier=SpfQualifier.PASS))
        assert result.level == RiskLevel.HIGH

    def test_spf_neutral_all_is_high(self):
        result = classify(spf=spf_result(all_qualifier=SpfQualifier.NEUTRAL))
        assert result.level == RiskLevel.HIGH

    def test_no_dmarc_justification_mentions_dmarc(self):
        result = classify(dmarc=dmarc_result(present=False))
        assert any("DMARC" in j for j in result.justification)

    def test_no_spf_justification_mentions_spf(self):
        result = classify(spf=spf_result(present=False))
        assert any("SPF" in j for j in result.justification)

    def test_pass_all_justification_mentions_all(self):
        result = classify(spf=spf_result(all_qualifier=SpfQualifier.PASS))
        assert any("all" in j.lower() or "internet" in j.lower() for j in result.justification)


class TestMediumRisk:
    def test_dmarc_none_policy_is_medium(self):
        result = classify(dmarc=dmarc_result(policy=DmarcPolicy.NONE, progression_stage=1))
        assert result.level == RiskLevel.MEDIUM

    def test_spf_softfail_is_medium(self):
        result = classify(spf=spf_result(all_qualifier=SpfQualifier.SOFTFAIL))
        assert result.level == RiskLevel.MEDIUM

    def test_dkim_checked_absent_is_medium(self):
        result = classify(dkim=dkim_result(checked=True, present=False))
        assert result.level == RiskLevel.MEDIUM

    def test_dmarc_none_justification_mentions_none(self):
        result = classify(dmarc=dmarc_result(policy=DmarcPolicy.NONE, progression_stage=1))
        assert any("none" in j.lower() or "monitoring" in j.lower() for j in result.justification)

    def test_softfail_justification_mentions_softfail(self):
        result = classify(spf=spf_result(all_qualifier=SpfQualifier.SOFTFAIL))
        assert any("softfail" in j.lower() or "~all" in j for j in result.justification)


class TestLowRisk:
    def test_full_protection_with_reject_is_low(self):
        result = classify(
            spf=spf_result(all_qualifier=SpfQualifier.FAIL),
            dkim=dkim_result(checked=True, present=True),
            dmarc=dmarc_result(policy=DmarcPolicy.REJECT),
        )
        assert result.level == RiskLevel.LOW

    def test_quarantine_with_dkim_and_hard_fail_is_low(self):
        result = classify(
            spf=spf_result(all_qualifier=SpfQualifier.FAIL),
            dkim=dkim_result(checked=True, present=True),
            dmarc=dmarc_result(policy=DmarcPolicy.QUARANTINE, progression_stage=3),
        )
        assert result.level == RiskLevel.LOW

    def test_low_justification_has_three_items(self):
        result = classify(
            spf=spf_result(all_qualifier=SpfQualifier.FAIL),
            dkim=dkim_result(checked=True, present=True),
            dmarc=dmarc_result(policy=DmarcPolicy.REJECT),
        )
        assert len(result.justification) == 3

    def test_unchecked_dkim_falls_to_default_medium(self):
        # DKIM unchecked (no selector) → _is_medium skips it, but _is_low requires
        # dkim.present=True, so unverified DKIM cannot achieve LOW (falls to default MEDIUM)
        result = classify(
            spf=spf_result(all_qualifier=SpfQualifier.FAIL),
            dkim=dkim_result(checked=False, present=False),
            dmarc=dmarc_result(policy=DmarcPolicy.REJECT),
        )
        assert result.level == RiskLevel.MEDIUM


class TestIssueCollection:
    def test_no_dmarc_generates_dmarc_001(self):
        result = classify(dmarc=dmarc_result(present=False))
        assert any(i.id == "DMARC-001" for i in result.issues)

    def test_issues_sorted_by_priority(self):
        result = classify(
            spf=spf_result(present=False),
            dmarc=dmarc_result(present=False),
        )
        priorities = [i.priority for i in result.issues]
        assert priorities == sorted(priorities)

    def test_dkim_not_checked_generates_dkim_002(self):
        result = classify(dkim=dkim_result(checked=False))
        assert any(i.id == "DKIM-002" for i in result.issues)

    def test_dkim_checked_absent_generates_dkim_001(self):
        result = classify(dkim=dkim_result(checked=True, present=False))
        assert any(i.id == "DKIM-001" for i in result.issues)

    def test_dmarc_none_with_rua_generates_dmarc_003(self):
        result = classify(dmarc=dmarc_result(
            policy=DmarcPolicy.NONE,
            rua=["dmarc@example.com"],
            progression_stage=1,
        ))
        assert any(i.id == "DMARC-003" for i in result.issues)

    def test_dmarc_none_without_rua_generates_dmarc_002(self):
        result = classify(dmarc=dmarc_result(
            policy=DmarcPolicy.NONE,
            rua=[],
            progression_stage=1,
        ))
        assert any(i.id == "DMARC-002" for i in result.issues)

    def test_clean_config_has_no_critical_issues(self):
        result = classify(
            spf=spf_result(all_qualifier=SpfQualifier.FAIL),
            dkim=dkim_result(checked=True, present=True),
            dmarc=dmarc_result(policy=DmarcPolicy.REJECT),
        )
        critical = [i for i in result.issues if i.severity == "critical"]
        assert critical == []
