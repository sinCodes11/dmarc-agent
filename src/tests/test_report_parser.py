"""Tests for ReportParser — XML parsing, statistics, classification, recommendations."""

import gzip
import json
import zipfile
from datetime import datetime, timezone

import pytest

from dmarc_agent.exceptions import DmarcParseError
from dmarc_agent.report_parser import ReportParser

# ── Sample XML fixtures ───────────────────────────────────────────────────────

# Unix timestamps: 2024-01-01 00:00:00 UTC → 2024-01-02 00:00:00 UTC
_BEGIN_TS = 1704067200
_END_TS = 1704153600


def _make_xml(records_xml: str = "", policy: str = "none", pct: int = 100) -> bytes:
    """Build a minimal valid DMARC aggregate report XML."""
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<feedback>
  <report_metadata>
    <org_name>Test Reporter</org_name>
    <email>dmarc@reporter.example</email>
    <report_id>test-report-001</report_id>
    <date_range>
      <begin>{_BEGIN_TS}</begin>
      <end>{_END_TS}</end>
    </date_range>
  </report_metadata>
  <policy_published>
    <domain>example.com</domain>
    <adkim>r</adkim>
    <aspf>r</aspf>
    <p>{policy}</p>
    <pct>{pct}</pct>
  </policy_published>
  {records_xml}
</feedback>""".encode()


def _record(
    source_ip="1.2.3.4",
    count=10,
    dkim_eval="pass",
    spf_eval="pass",
    disposition="none",
    dkim_result="pass",
    spf_result="pass",
    header_from="example.com",
) -> str:
    return f"""
  <record>
    <row>
      <source_ip>{source_ip}</source_ip>
      <count>{count}</count>
      <policy_evaluated>
        <disposition>{disposition}</disposition>
        <dkim>{dkim_eval}</dkim>
        <spf>{spf_eval}</spf>
      </policy_evaluated>
    </row>
    <identifiers>
      <header_from>{header_from}</header_from>
    </identifiers>
    <auth_results>
      <dkim>
        <domain>example.com</domain>
        <selector>selector1</selector>
        <result>{dkim_result}</result>
      </dkim>
      <spf>
        <domain>example.com</domain>
        <result>{spf_result}</result>
      </spf>
    </auth_results>
  </record>"""


def _write_xml(tmp_path, xml: bytes, name="report.xml"):
    p = tmp_path / name
    p.write_bytes(xml)
    return str(p)


def _write_gz(tmp_path, xml: bytes, name="report.xml.gz"):
    p = tmp_path / name
    with gzip.open(str(p), "wb") as f:
        f.write(xml)
    return str(p)


def _write_zip(tmp_path, xml: bytes, xml_name="report.xml", zip_name="report.zip"):
    p = tmp_path / zip_name
    with zipfile.ZipFile(str(p), "w") as zf:
        zf.writestr(xml_name, xml)
    return str(p)


# ── Metadata extraction ───────────────────────────────────────────────────────

class TestMetadataExtraction:
    def test_org_name_extracted(self, tmp_path):
        path = _write_xml(tmp_path, _make_xml(_record()))
        result = ReportParser().parse_file(path)
        assert result.metadata.org_name == "Test Reporter"

    def test_report_id_extracted(self, tmp_path):
        path = _write_xml(tmp_path, _make_xml(_record()))
        result = ReportParser().parse_file(path)
        assert result.metadata.report_id == "test-report-001"

    def test_begin_timestamp_parsed(self, tmp_path):
        path = _write_xml(tmp_path, _make_xml(_record()))
        result = ReportParser().parse_file(path)
        assert result.metadata.begin == datetime.fromtimestamp(_BEGIN_TS, tz=timezone.utc)

    def test_end_timestamp_parsed(self, tmp_path):
        path = _write_xml(tmp_path, _make_xml(_record()))
        result = ReportParser().parse_file(path)
        assert result.metadata.end == datetime.fromtimestamp(_END_TS, tz=timezone.utc)

    def test_duration_hours_calculated(self, tmp_path):
        path = _write_xml(tmp_path, _make_xml(_record()))
        result = ReportParser().parse_file(path)
        assert result.metadata.duration_hours == pytest.approx(24.0)

    def test_email_extracted(self, tmp_path):
        path = _write_xml(tmp_path, _make_xml(_record()))
        result = ReportParser().parse_file(path)
        assert result.metadata.email == "dmarc@reporter.example"


# ── Policy published extraction ───────────────────────────────────────────────

class TestPolicyPublished:
    def test_domain_extracted(self, tmp_path):
        path = _write_xml(tmp_path, _make_xml(_record()))
        result = ReportParser().parse_file(path)
        assert result.policy_published.domain == "example.com"

    def test_policy_none_extracted(self, tmp_path):
        path = _write_xml(tmp_path, _make_xml(_record(), policy="none"))
        result = ReportParser().parse_file(path)
        assert result.policy_published.policy == "none"

    def test_policy_quarantine_extracted(self, tmp_path):
        path = _write_xml(tmp_path, _make_xml(_record(), policy="quarantine"))
        result = ReportParser().parse_file(path)
        assert result.policy_published.policy == "quarantine"

    def test_policy_reject_extracted(self, tmp_path):
        path = _write_xml(tmp_path, _make_xml(_record(), policy="reject"))
        result = ReportParser().parse_file(path)
        assert result.policy_published.policy == "reject"

    def test_pct_extracted(self, tmp_path):
        path = _write_xml(tmp_path, _make_xml(_record(), pct=10))
        result = ReportParser().parse_file(path)
        assert result.policy_published.pct == 10

    def test_pct_defaults_to_100(self, tmp_path):
        xml = _make_xml(_record()).replace(b"<pct>100</pct>", b"")
        path = _write_xml(tmp_path, xml)
        result = ReportParser().parse_file(path)
        assert result.policy_published.pct == 100

    def test_adkim_extracted(self, tmp_path):
        path = _write_xml(tmp_path, _make_xml(_record()))
        result = ReportParser().parse_file(path)
        assert result.policy_published.adkim == "r"


# ── Record parsing ────────────────────────────────────────────────────────────

class TestRecordParsing:
    def test_single_record_parsed(self, tmp_path):
        path = _write_xml(tmp_path, _make_xml(_record()))
        result = ReportParser().parse_file(path)
        assert len(result.records) == 1

    def test_multiple_records_parsed(self, tmp_path):
        recs = _record("1.2.3.4", 10) + _record("5.6.7.8", 5)
        path = _write_xml(tmp_path, _make_xml(recs))
        result = ReportParser().parse_file(path)
        assert len(result.records) == 2

    def test_source_ip_extracted(self, tmp_path):
        path = _write_xml(tmp_path, _make_xml(_record("192.168.1.1", 3)))
        result = ReportParser().parse_file(path)
        assert result.records[0].source_ip == "192.168.1.1"

    def test_count_extracted(self, tmp_path):
        path = _write_xml(tmp_path, _make_xml(_record(count=42)))
        result = ReportParser().parse_file(path)
        assert result.records[0].count == 42

    def test_dkim_eval_extracted(self, tmp_path):
        path = _write_xml(tmp_path, _make_xml(_record(dkim_eval="fail")))
        result = ReportParser().parse_file(path)
        assert result.records[0].policy_evaluated.dkim == "fail"

    def test_spf_eval_extracted(self, tmp_path):
        path = _write_xml(tmp_path, _make_xml(_record(spf_eval="fail")))
        result = ReportParser().parse_file(path)
        assert result.records[0].policy_evaluated.spf == "fail"

    def test_disposition_extracted(self, tmp_path):
        path = _write_xml(tmp_path, _make_xml(_record(disposition="quarantine")))
        result = ReportParser().parse_file(path)
        assert result.records[0].policy_evaluated.disposition == "quarantine"

    def test_header_from_extracted(self, tmp_path):
        path = _write_xml(tmp_path, _make_xml(_record(header_from="sender.example.com")))
        result = ReportParser().parse_file(path)
        assert result.records[0].header_from == "sender.example.com"

    def test_dkim_auth_result_extracted(self, tmp_path):
        path = _write_xml(tmp_path, _make_xml(_record(dkim_result="pass")))
        result = ReportParser().parse_file(path)
        assert result.records[0].dkim_auth[0].result == "pass"

    def test_dkim_selector_extracted(self, tmp_path):
        path = _write_xml(tmp_path, _make_xml(_record()))
        result = ReportParser().parse_file(path)
        assert result.records[0].dkim_auth[0].selector == "selector1"

    def test_spf_auth_result_extracted(self, tmp_path):
        path = _write_xml(tmp_path, _make_xml(_record(spf_result="fail")))
        result = ReportParser().parse_file(path)
        assert result.records[0].spf_auth[0].result == "fail"


# ── Statistics ────────────────────────────────────────────────────────────────

class TestStatistics:
    def test_total_messages_summed(self, tmp_path):
        recs = _record("1.1.1.1", 10) + _record("2.2.2.2", 5)
        path = _write_xml(tmp_path, _make_xml(recs))
        result = ReportParser().parse_file(path)
        assert result.statistics.total_messages == 15

    def test_dkim_pass_counted(self, tmp_path):
        recs = _record("1.1.1.1", 10, dkim_eval="pass") + _record("2.2.2.2", 5, dkim_eval="fail")
        path = _write_xml(tmp_path, _make_xml(recs))
        result = ReportParser().parse_file(path)
        assert result.statistics.dkim_pass == 10
        assert result.statistics.dkim_fail == 5

    def test_spf_pass_counted(self, tmp_path):
        recs = _record("1.1.1.1", 8, spf_eval="pass") + _record("2.2.2.2", 2, spf_eval="fail")
        path = _write_xml(tmp_path, _make_xml(recs))
        result = ReportParser().parse_file(path)
        assert result.statistics.spf_pass == 8
        assert result.statistics.spf_fail == 2

    def test_fully_aligned_counted(self, tmp_path):
        recs = (
            _record("1.1.1.1", 10, dkim_eval="pass", spf_eval="pass") +
            _record("2.2.2.2", 5, dkim_eval="fail", spf_eval="pass")
        )
        path = _write_xml(tmp_path, _make_xml(recs))
        result = ReportParser().parse_file(path)
        assert result.statistics.fully_aligned == 10

    def test_fully_failed_counted(self, tmp_path):
        recs = (
            _record("1.1.1.1", 3, dkim_eval="fail", spf_eval="fail") +
            _record("2.2.2.2", 7, dkim_eval="pass", spf_eval="pass")
        )
        path = _write_xml(tmp_path, _make_xml(recs))
        result = ReportParser().parse_file(path)
        assert result.statistics.fully_failed == 3

    def test_pass_rate_dkim_calculated(self, tmp_path):
        recs = _record("1.1.1.1", 90, dkim_eval="pass") + _record("2.2.2.2", 10, dkim_eval="fail")
        path = _write_xml(tmp_path, _make_xml(recs))
        result = ReportParser().parse_file(path)
        assert result.statistics.pass_rate_dkim == 90.0

    def test_pass_rate_overall_dmarc_pass(self, tmp_path):
        # DMARC passes if either DKIM or SPF passes
        recs = (
            _record("1.1.1.1", 5, dkim_eval="pass", spf_eval="fail") +
            _record("2.2.2.2", 5, dkim_eval="fail", spf_eval="fail")
        )
        path = _write_xml(tmp_path, _make_xml(recs))
        result = ReportParser().parse_file(path)
        assert result.statistics.pass_rate_overall == 50.0

    def test_unique_sources_counted(self, tmp_path):
        recs = _record("1.1.1.1", 5) + _record("2.2.2.2", 5) + _record("1.1.1.1", 3)
        path = _write_xml(tmp_path, _make_xml(recs))
        result = ReportParser().parse_file(path)
        assert result.statistics.unique_sources == 2

    def test_disposition_counts(self, tmp_path):
        recs = (
            _record("1.1.1.1", 5, disposition="none") +
            _record("2.2.2.2", 3, disposition="quarantine") +
            _record("3.3.3.3", 2, disposition="reject")
        )
        path = _write_xml(tmp_path, _make_xml(recs))
        result = ReportParser().parse_file(path)
        s = result.statistics
        assert s.disposition_none == 5
        assert s.disposition_quarantine == 3
        assert s.disposition_reject == 2

    def test_empty_records_returns_zero_stats(self, tmp_path):
        path = _write_xml(tmp_path, _make_xml(""))
        result = ReportParser().parse_file(path)
        assert result.statistics.total_messages == 0
        assert result.statistics.pass_rate_overall == 0.0


# ── Source classification ─────────────────────────────────────────────────────

class TestSourceClassification:
    def test_all_pass_is_legitimate(self, tmp_path):
        path = _write_xml(tmp_path, _make_xml(_record("1.2.3.4", 10, "pass", "pass")))
        result = ReportParser().parse_file(path)
        assert result.source_classifications[0].classification == "legitimate"
        assert result.source_classifications[0].confidence == "high"

    def test_all_fail_is_suspicious(self, tmp_path):
        path = _write_xml(tmp_path, _make_xml(_record("1.2.3.4", 10, "fail", "fail")))
        result = ReportParser().parse_file(path)
        assert result.source_classifications[0].classification == "suspicious"
        assert result.source_classifications[0].confidence == "high"

    def test_dkim_pass_spf_fail_is_forwarding(self, tmp_path):
        path = _write_xml(tmp_path, _make_xml(_record("1.2.3.4", 10, "pass", "fail")))
        result = ReportParser().parse_file(path)
        assert result.source_classifications[0].classification == "forwarding"

    def test_sources_sorted_by_volume(self, tmp_path):
        recs = _record("1.1.1.1", 5) + _record("2.2.2.2", 100)
        path = _write_xml(tmp_path, _make_xml(recs))
        result = ReportParser().parse_file(path)
        assert result.source_classifications[0].source_ip == "2.2.2.2"
        assert result.source_classifications[1].source_ip == "1.1.1.1"

    def test_pass_rate_on_source(self, tmp_path):
        path = _write_xml(tmp_path, _make_xml(_record("1.2.3.4", 10, "pass", "pass")))
        result = ReportParser().parse_file(path)
        assert result.source_classifications[0].pass_rate == 100.0

    def test_evidence_populated(self, tmp_path):
        path = _write_xml(tmp_path, _make_xml(_record("1.2.3.4", 10, "pass", "pass")))
        result = ReportParser().parse_file(path)
        assert len(result.source_classifications[0].evidence) > 0

    def test_message_count_on_source(self, tmp_path):
        path = _write_xml(tmp_path, _make_xml(_record("1.2.3.4", 42)))
        result = ReportParser().parse_file(path)
        assert result.source_classifications[0].message_count == 42


# ── Recommendations ───────────────────────────────────────────────────────────

class TestRecommendations:
    def test_none_policy_recommends_progress(self, tmp_path):
        path = _write_xml(tmp_path, _make_xml(_record(), policy="none"))
        result = ReportParser().parse_file(path)
        actions = [r["action"].lower() for r in result.recommendations]
        assert any("quarantine" in a for a in actions)

    def test_suspicious_source_generates_recommendation(self, tmp_path):
        path = _write_xml(tmp_path, _make_xml(_record("1.2.3.4", 10, "fail", "fail")))
        result = ReportParser().parse_file(path)
        actions = [r["action"].lower() for r in result.recommendations]
        assert any("unauthorized" in a or "investigat" in a for a in actions)

    def test_no_urgent_recommendations_for_clean_reject(self, tmp_path):
        path = _write_xml(tmp_path, _make_xml(_record("1.2.3.4", 100, "pass", "pass"), policy="reject"))
        result = ReportParser().parse_file(path)
        high_prio = [r for r in result.recommendations if r["priority"] == "high"]
        assert high_prio == []

    def test_low_pass_rate_generates_high_recommendation(self, tmp_path):
        # 80% pass rate should trigger high recommendation
        recs = _record("1.1.1.1", 80, "pass", "pass") + _record("2.2.2.2", 20, "fail", "fail")
        path = _write_xml(tmp_path, _make_xml(recs, policy="reject"))
        result = ReportParser().parse_file(path)
        high = [r for r in result.recommendations if r["priority"] == "high"]
        assert len(high) > 0


# ── File format support ───────────────────────────────────────────────────────

class TestFileFormats:
    def test_plain_xml_parsed(self, tmp_path):
        path = _write_xml(tmp_path, _make_xml(_record()))
        result = ReportParser().parse_file(path)
        assert result.metadata.org_name == "Test Reporter"

    def test_gzip_xml_parsed(self, tmp_path):
        path = _write_gz(tmp_path, _make_xml(_record()))
        result = ReportParser().parse_file(path)
        assert result.metadata.org_name == "Test Reporter"

    def test_zip_xml_parsed(self, tmp_path):
        path = _write_zip(tmp_path, _make_xml(_record()))
        result = ReportParser().parse_file(path)
        assert result.metadata.org_name == "Test Reporter"

    def test_statistics_same_across_formats(self, tmp_path):
        xml = _make_xml(_record("1.2.3.4", 7))
        xml_result = ReportParser().parse_file(_write_xml(tmp_path, xml))
        gz_result = ReportParser().parse_file(_write_gz(tmp_path, xml))
        zip_result = ReportParser().parse_file(_write_zip(tmp_path, xml))
        assert xml_result.statistics.total_messages == gz_result.statistics.total_messages == zip_result.statistics.total_messages == 7


# ── Error handling ────────────────────────────────────────────────────────────

class TestErrorHandling:
    def test_malformed_xml_raises(self, tmp_path):
        path = _write_xml(tmp_path, b"not valid xml <<<")
        with pytest.raises(DmarcParseError, match="Malformed XML"):
            ReportParser().parse_file(path)

    def test_missing_report_metadata_raises(self, tmp_path):
        xml = b"<feedback><policy_published><domain>x.com</domain><p>none</p></policy_published></feedback>"
        path = _write_xml(tmp_path, xml)
        with pytest.raises(DmarcParseError, match="report_metadata"):
            ReportParser().parse_file(path)

    def test_missing_policy_published_raises(self, tmp_path):
        xml = b"""<feedback>
          <report_metadata>
            <org_name>X</org_name><email>x@x.com</email><report_id>1</report_id>
            <date_range><begin>1704067200</begin><end>1704153600</end></date_range>
          </report_metadata>
        </feedback>"""
        path = _write_xml(tmp_path, xml)
        with pytest.raises(DmarcParseError, match="policy_published"):
            ReportParser().parse_file(path)

    def test_empty_records_triggers_validation_warning(self, tmp_path):
        path = _write_xml(tmp_path, _make_xml(""))
        result = ReportParser().parse_file(path)
        assert any("No records" in m for m in result.validation_messages)

    def test_invalid_pct_uses_default_and_warns(self, tmp_path):
        xml = _make_xml(_record()).replace(b"<pct>100</pct>", b"<pct>bad</pct>")
        path = _write_xml(tmp_path, xml)
        result = ReportParser().parse_file(path)
        assert result.policy_published.pct == 100
        assert any("pct" in m.lower() for m in result.validation_messages)

    def test_zip_with_no_xml_raises(self, tmp_path):
        p = tmp_path / "empty.zip"
        with zipfile.ZipFile(str(p), "w") as zf:
            zf.writestr("notes.txt", "no xml here")
        with pytest.raises(DmarcParseError, match="No XML file"):
            ReportParser().parse_file(str(p))


# ── CLI integration ───────────────────────────────────────────────────────────

class TestCLIParseReport:
    def test_text_output_exits_zero(self, tmp_path):
        from unittest.mock import patch
        from click.testing import CliRunner
        from dmarc_agent.cli import cli

        path = _write_xml(tmp_path, _make_xml(_record()))
        runner = CliRunner()
        result = runner.invoke(cli, ["parse-report", path])
        assert result.exit_code == 0

    def test_json_output_is_valid(self, tmp_path):
        from unittest.mock import patch
        from click.testing import CliRunner
        from dmarc_agent.cli import cli

        path = _write_xml(tmp_path, _make_xml(_record()))
        runner = CliRunner()
        result = runner.invoke(cli, ["parse-report", path, "--format", "json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "report" in data
        assert "statistics" in data["report"]

    def test_json_contains_domain(self, tmp_path):
        from click.testing import CliRunner
        from dmarc_agent.cli import cli

        path = _write_xml(tmp_path, _make_xml(_record()))
        runner = CliRunner()
        result = runner.invoke(cli, ["parse-report", path, "--format", "json"])
        data = json.loads(result.output)
        assert data["report"]["policy_published"]["domain"] == "example.com"

    def test_invalid_xml_exits_nonzero(self, tmp_path):
        from click.testing import CliRunner
        from dmarc_agent.cli import cli

        p = tmp_path / "bad.xml"
        p.write_bytes(b"<not valid")
        runner = CliRunner()
        result = runner.invoke(cli, ["parse-report", str(p)])
        assert result.exit_code != 0
