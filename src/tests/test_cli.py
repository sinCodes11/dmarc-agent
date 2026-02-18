"""Integration tests for all four CLI subcommands with mocked DNS."""

import json
from unittest.mock import patch

from click.testing import CliRunner

from dmarc_agent.cli import cli

from .helpers import mock_fetcher

DOMAIN = "example.com"


def make_full_fetcher(spf=None, dmarc=None, dkim=None, selector="google"):
    """Build a mock fetcher for a complete analyze run."""
    mapping = {
        DOMAIN: [spf] if spf else [],
        f"_dmarc.{DOMAIN}": [dmarc] if dmarc else [],
    }
    if dkim and selector:
        mapping[f"{selector}._domainkey.{DOMAIN}"] = [dkim]
    return mock_fetcher(mapping)


def run(args, fetcher=None):
    if fetcher is None:
        fetcher = mock_fetcher()
    with patch("dmarc_agent.cli.create_fetcher", return_value=fetcher):
        runner = CliRunner()
        return runner.invoke(cli, args)


class TestAnalyzeCommand:
    def test_exits_zero_on_success(self):
        fetcher = make_full_fetcher(spf="v=spf1 include:_spf.google.com -all")
        result = run(["analyze", DOMAIN, "--format", "json"], fetcher)
        assert result.exit_code == 0

    def test_json_output_is_valid_json(self):
        fetcher = make_full_fetcher(spf="v=spf1 ~all")
        result = run(["analyze", DOMAIN, "--format", "json"], fetcher)
        data = json.loads(result.output)
        assert isinstance(data, dict)

    def test_json_output_contains_domain(self):
        fetcher = make_full_fetcher()
        result = run(["analyze", DOMAIN, "--format", "json"], fetcher)
        data = json.loads(result.output)
        assert data["domain"] == DOMAIN

    def test_json_output_contains_risk_level(self):
        fetcher = make_full_fetcher()
        result = run(["analyze", DOMAIN, "--format", "json"], fetcher)
        data = json.loads(result.output)
        assert "risk_level" in data
        assert data["risk_level"] in ("HIGH", "MEDIUM", "LOW")

    def test_no_spf_no_dmarc_produces_high_risk(self):
        fetcher = make_full_fetcher()  # empty: no SPF, no DMARC
        result = run(["analyze", DOMAIN, "--format", "json"], fetcher)
        data = json.loads(result.output)
        assert data["risk_level"] == "HIGH"

    def test_json_output_has_security_status(self):
        fetcher = make_full_fetcher()
        result = run(["analyze", DOMAIN, "--format", "json"], fetcher)
        data = json.loads(result.output)
        assert "security_status" in data
        assert "spf" in data["security_status"]
        assert "dmarc" in data["security_status"]

    def test_dkim_selector_option_accepted(self):
        fetcher = make_full_fetcher(
            dkim="v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQ==",
        )
        result = run(["analyze", DOMAIN, "--dkim-selector", "google", "--format", "json"], fetcher)
        assert result.exit_code == 0

    def test_write_to_output_file(self, tmp_path):
        out = str(tmp_path / "report.json")
        fetcher = make_full_fetcher()
        result = run(["analyze", DOMAIN, "--format", "json", "--output", out], fetcher)
        assert result.exit_code == 0
        with open(out) as f:
            data = json.load(f)
        assert data["domain"] == DOMAIN


class TestCheckSpfCommand:
    def test_exits_zero_with_spf_present(self):
        fetcher = mock_fetcher({DOMAIN: ["v=spf1 -all"]})
        result = run(["check-spf", DOMAIN], fetcher)
        assert result.exit_code == 0

    def test_exits_zero_with_no_spf(self):
        fetcher = mock_fetcher({DOMAIN: []})
        result = run(["check-spf", DOMAIN], fetcher)
        assert result.exit_code == 0

    def test_produces_output(self):
        fetcher = mock_fetcher({DOMAIN: ["v=spf1 include:_spf.google.com -all"]})
        result = run(["check-spf", DOMAIN], fetcher)
        assert result.output.strip() != ""


class TestCheckDmarcCommand:
    def test_exits_zero_with_dmarc_present(self):
        fetcher = mock_fetcher({
            f"_dmarc.{DOMAIN}": ["v=DMARC1; p=none; rua=mailto:r@example.com"]
        })
        result = run(["check-dmarc", DOMAIN], fetcher)
        assert result.exit_code == 0

    def test_exits_zero_with_no_dmarc(self):
        fetcher = mock_fetcher({f"_dmarc.{DOMAIN}": []})
        result = run(["check-dmarc", DOMAIN], fetcher)
        assert result.exit_code == 0

    def test_produces_output(self):
        fetcher = mock_fetcher({
            f"_dmarc.{DOMAIN}": ["v=DMARC1; p=quarantine; rua=mailto:r@example.com"]
        })
        result = run(["check-dmarc", DOMAIN], fetcher)
        assert result.output.strip() != ""


class TestVerifyDkimCommand:
    def test_exits_zero_when_key_found(self):
        key = "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQ=="
        fetcher = mock_fetcher({f"google._domainkey.{DOMAIN}": [key]})
        result = run(["verify-dkim", "google", DOMAIN], fetcher)
        assert result.exit_code == 0

    def test_exits_zero_when_key_absent(self):
        fetcher = mock_fetcher({f"google._domainkey.{DOMAIN}": []})
        result = run(["verify-dkim", "google", DOMAIN], fetcher)
        assert result.exit_code == 0

    def test_produces_output(self):
        fetcher = mock_fetcher({f"google._domainkey.{DOMAIN}": []})
        result = run(["verify-dkim", "google", DOMAIN], fetcher)
        assert result.output.strip() != ""
