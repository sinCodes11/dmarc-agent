"""Unit tests for RecordGenerator — remediation plans, client explanations, phases."""

from dmarc_agent.models import DmarcPolicy, RiskAssessment, RiskLevel, SpfQualifier
from dmarc_agent.record_generator import RecordGenerator

from .helpers import dkim_result, dmarc_result, spf_result

DOMAIN = "example.com"


def generate(spf=None, dkim=None, dmarc=None):
    s = spf or spf_result()
    d = dkim or dkim_result()
    r = dmarc or dmarc_result()
    return RecordGenerator().generate(DOMAIN, s, d, r)


def explain(level):
    assessment = RiskAssessment(level=level, justification=[], issues=[])
    return RecordGenerator().generate_client_explanation(assessment, DOMAIN)


class TestClientExplanation:
    def test_high_mentions_spoofing(self):
        assert "spoof" in explain(RiskLevel.HIGH).lower()

    def test_medium_mentions_partial_or_enforcement(self):
        text = explain(RiskLevel.MEDIUM).lower()
        assert "partial" in text or "enforced" in text or "monitoring" in text

    def test_low_mentions_maintenance_or_monitoring(self):
        text = explain(RiskLevel.LOW).lower()
        assert "monitor" in text or "maintenance" in text or "review" in text

    def test_all_levels_include_domain_name(self):
        for level in (RiskLevel.HIGH, RiskLevel.MEDIUM, RiskLevel.LOW):
            assert DOMAIN in explain(level)

    def test_high_mentions_recommended_fixes(self):
        assert "fix" in explain(RiskLevel.HIGH).lower() or "recommended" in explain(RiskLevel.HIGH).lower()


class TestSpfSpec:
    def test_no_spec_when_hard_fail_and_no_misconfigs(self):
        plan = generate(spf=spf_result(all_qualifier=SpfQualifier.FAIL, misconfigurations=[]))
        assert plan.spf is None

    def test_spec_generated_when_softfail(self):
        plan = generate(spf=spf_result(all_qualifier=SpfQualifier.SOFTFAIL))
        assert plan.spf is not None

    def test_spec_generated_when_spf_absent(self):
        plan = generate(spf=spf_result(present=False))
        assert plan.spf is not None

    def test_spf_spec_record_type_is_txt(self):
        plan = generate(spf=spf_result(present=False))
        assert plan.spf.record_type == "TXT"

    def test_spf_spec_name_is_at_sign(self):
        plan = generate(spf=spf_result(present=False))
        assert plan.spf.name == "@"

    def test_spf_spec_purpose_mentions_create_when_absent(self):
        plan = generate(spf=spf_result(present=False))
        assert "create" in plan.spf.purpose.lower() or "spf" in plan.spf.purpose.lower()

    def test_spf_spec_purpose_mentions_update_when_present(self):
        from dmarc_agent.models import SpfMisconfiguration
        mc = SpfMisconfiguration(
            id="SPF-HIGH-001", name="softfail_all", severity="high", description="", remediation=""
        )
        plan = generate(spf=spf_result(all_qualifier=SpfQualifier.SOFTFAIL, misconfigurations=[mc]))
        assert "update" in plan.spf.purpose.lower()


class TestDmarcSpec:
    def test_no_spec_when_reject_with_rua(self):
        plan = generate(dmarc=dmarc_result())  # default: reject + rua
        assert plan.dmarc is None

    def test_spec_generated_when_dmarc_absent(self):
        plan = generate(dmarc=dmarc_result(present=False))
        assert plan.dmarc is not None

    def test_spec_generated_when_policy_is_none(self):
        plan = generate(dmarc=dmarc_result(policy=DmarcPolicy.NONE, progression_stage=1))
        assert plan.dmarc is not None

    def test_dmarc_spec_record_type_is_txt(self):
        plan = generate(dmarc=dmarc_result(present=False))
        assert plan.dmarc.record_type == "TXT"

    def test_dmarc_spec_name_is_underscore_dmarc(self):
        plan = generate(dmarc=dmarc_result(present=False))
        assert plan.dmarc.name == "_dmarc"

    def test_dmarc_spec_has_stage(self):
        plan = generate(dmarc=dmarc_result(present=False))
        assert plan.dmarc.stage is not None

    def test_dmarc_spec_has_next_step(self):
        plan = generate(dmarc=dmarc_result(present=False))
        assert plan.dmarc.next_step is not None


class TestDkimAction:
    def test_no_action_when_dkim_present(self):
        plan = generate(dkim=dkim_result(present=True))
        assert plan.dkim_action is None

    def test_action_when_dkim_not_checked(self):
        plan = generate(dkim=dkim_result(checked=False, present=False))
        assert plan.dkim_action is not None
        assert "provider" in plan.dkim_action.lower()

    def test_action_when_selector_not_found(self):
        plan = generate(dkim=dkim_result(checked=True, present=False))
        assert plan.dkim_action is not None

    def test_action_never_contains_key_value(self):
        # Agent must never provide DKIM key values
        plan = generate(dkim=dkim_result(checked=True, present=False))
        # Should reference provider, not include a real key
        assert "MIG" not in (plan.dkim_action or "")  # No base64 key fragments


class TestImplementationPhases:
    def test_phases_present_when_all_absent(self):
        plan = generate(
            spf=spf_result(present=False),
            dkim=dkim_result(checked=False),
            dmarc=dmarc_result(present=False),
        )
        assert len(plan.implementation_phases) > 0

    def test_dmarc_phase_before_spf_phase(self):
        plan = generate(
            spf=spf_result(present=False),
            dkim=dkim_result(present=True),  # no DKIM phase
            dmarc=dmarc_result(present=False),
        )
        titles = [p.title for p in plan.implementation_phases]
        dmarc_idx = next(i for i, t in enumerate(titles) if "DMARC" in t and "Enforcement" not in t)
        spf_idx = next(i for i, t in enumerate(titles) if "SPF" in t)
        assert dmarc_idx < spf_idx

    def test_no_phases_when_all_complete(self):
        plan = generate(
            spf=spf_result(all_qualifier=SpfQualifier.FAIL, misconfigurations=[]),
            dkim=dkim_result(present=True),
            dmarc=dmarc_result(policy=DmarcPolicy.REJECT, rua=["d@example.com"]),
        )
        assert len(plan.implementation_phases) == 0

    def test_each_phase_has_verification_command(self):
        plan = generate(
            spf=spf_result(present=False),
            dkim=dkim_result(present=True),
            dmarc=dmarc_result(present=False),
        )
        for phase in plan.implementation_phases:
            assert phase.verification

    def test_phases_numbered_sequentially(self):
        plan = generate(
            spf=spf_result(present=False),
            dkim=dkim_result(checked=False),
            dmarc=dmarc_result(present=False),
        )
        numbers = [p.phase for p in plan.implementation_phases]
        assert numbers == list(range(1, len(numbers) + 1))
