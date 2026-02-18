"""Tests for the REST API server (api_server.py).

Uses FastAPI's TestClient which drives the ASGI app in-process —
no real HTTP socket needed.  DNS calls are patched via unittest.mock.
"""

import json
import os
import time
import unittest
from unittest.mock import MagicMock, patch

import pytest


# ── Helpers — patch DMARC_API_KEY before importing the app ────────────────────

TEST_API_KEY = "test-key-that-is-long-enough-to-pass-validation"
AUTH_HEADER = {"Authorization": f"Bearer {TEST_API_KEY}"}


@pytest.fixture(autouse=True)
def _set_api_key(monkeypatch):
    monkeypatch.setenv("DMARC_API_KEY", TEST_API_KEY)


# Import after setting env var so _get_api_key() picks it up.
@pytest.fixture()
def client(monkeypatch):
    monkeypatch.setenv("DMARC_API_KEY", TEST_API_KEY)
    from fastapi.testclient import TestClient  # noqa: PLC0415

    # Clear in-memory job/batch stores and rate limiter between tests.
    from dmarc_agent import api_server  # noqa: PLC0415

    api_server._jobs.clear()
    api_server._batches.clear()
    api_server._rate_store.clear()

    return TestClient(api_server.app, raise_server_exceptions=False)


# ── Minimal fake analysis result returned by mocked _analyse_domain ───────────

_FAKE_RESULT = {
    "domain": "example.com",
    "timestamp": "2024-01-01T00:00:00Z",
    "risk_level": "MEDIUM",
    "security_status": {"spf": {}, "dkim": {}, "dmarc": {}},
    "recommended_records": {},
    "findings": [],
    "implementation_priority": [],
    "business_impact": "Test impact.",
    "next_steps": [],
}


def _make_mock_analyse():
    """Return a patch target that always returns _FAKE_RESULT."""
    return patch("dmarc_agent.api_server._analyse_domain", return_value=_FAKE_RESULT)


# ── Health ────────────────────────────────────────────────────────────────────


class TestHealth:
    def test_health_ok(self, client):
        r = client.get("/api/v1/health")
        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "ok"
        assert "timestamp" in data
        assert "version" in data

    def test_health_no_auth_required(self, client):
        """Health endpoint requires no auth."""
        r = client.get("/api/v1/health")
        assert r.status_code == 200


# ── Auth ──────────────────────────────────────────────────────────────────────


class TestAuth:
    def test_missing_auth_header_returns_401(self, client):
        r = client.post("/api/v1/analyze", json={"domain": "example.com"})
        assert r.status_code == 401

    def test_wrong_token_returns_401(self, client):
        r = client.post(
            "/api/v1/analyze",
            json={"domain": "example.com"},
            headers={"Authorization": "Bearer wrong-key"},
        )
        assert r.status_code == 401
        assert r.json()["error"]["code"] == "AUTH_FAILED"

    def test_correct_token_accepted(self, client):
        with _make_mock_analyse():
            r = client.post(
                "/api/v1/analyze",
                json={"domain": "example.com"},
                headers=AUTH_HEADER,
            )
        assert r.status_code == 200


# ── POST /api/v1/analyze ──────────────────────────────────────────────────────


class TestAnalyzeSync:
    def test_returns_analysis_result(self, client):
        with _make_mock_analyse():
            r = client.post("/api/v1/analyze", json={"domain": "example.com"}, headers=AUTH_HEADER)
        assert r.status_code == 200
        data = r.json()
        assert data["domain"] == "example.com"
        assert data["risk_level"] == "MEDIUM"
        assert "request_id" in data

    def test_domain_normalised_to_lowercase(self, client):
        with _make_mock_analyse() as mock_fn:
            client.post("/api/v1/analyze", json={"domain": "EXAMPLE.COM"}, headers=AUTH_HEADER)
        mock_fn.assert_called_once_with("example.com", None)

    def test_dkim_selector_passed_through(self, client):
        with _make_mock_analyse() as mock_fn:
            client.post(
                "/api/v1/analyze",
                json={"domain": "example.com", "options": {"dkim_selector": "google"}},
                headers=AUTH_HEADER,
            )
        mock_fn.assert_called_once_with("example.com", "google")

    def test_empty_domain_returns_422(self, client):
        r = client.post("/api/v1/analyze", json={"domain": ""}, headers=AUTH_HEADER)
        assert r.status_code == 422

    def test_missing_domain_field_returns_422(self, client):
        r = client.post("/api/v1/analyze", json={}, headers=AUTH_HEADER)
        assert r.status_code == 422

    def test_invalid_domain_returns_400(self, client):
        from dmarc_agent.exceptions import InvalidDomainError  # noqa: PLC0415

        with patch("dmarc_agent.api_server._analyse_domain", side_effect=InvalidDomainError("bad")):
            r = client.post("/api/v1/analyze", json={"domain": "bad!"}, headers=AUTH_HEADER)
        assert r.status_code == 400
        assert r.json()["error"]["code"] == "INVALID_DOMAIN"

    def test_dns_error_returns_503(self, client):
        from dmarc_agent.exceptions import DmarcAgentError  # noqa: PLC0415

        with patch("dmarc_agent.api_server._analyse_domain", side_effect=DmarcAgentError("dns fail")):
            r = client.post("/api/v1/analyze", json={"domain": "example.com"}, headers=AUTH_HEADER)
        assert r.status_code == 503
        assert r.json()["error"]["code"] == "DNS_TIMEOUT"


# ── POST /api/v1/analyze/async ────────────────────────────────────────────────


class TestAnalyzeAsync:
    def test_returns_202_with_request_id(self, client):
        with _make_mock_analyse():
            r = client.post("/api/v1/analyze/async", json={"domain": "example.com"}, headers=AUTH_HEADER)
        assert r.status_code == 202
        data = r.json()
        assert "request_id" in data
        assert data["status"] in ("queued", "processing", "completed")
        assert "status_url" in data

    def test_status_url_uses_request_id(self, client):
        with _make_mock_analyse():
            r = client.post("/api/v1/analyze/async", json={"domain": "example.com"}, headers=AUTH_HEADER)
        rid = r.json()["request_id"]
        assert r.json()["status_url"] == f"/api/v1/status/{rid}"


# ── GET /api/v1/status/{request_id} ──────────────────────────────────────────


class TestJobStatus:
    def test_unknown_request_id_returns_404(self, client):
        r = client.get("/api/v1/status/nonexistent-uuid", headers=AUTH_HEADER)
        assert r.status_code == 404
        assert r.json()["error"]["code"] == "NOT_FOUND"

    def test_completed_job_returns_result(self, client):
        """Submit async job, wait for ThreadPoolExecutor, then poll status."""
        with _make_mock_analyse():
            r = client.post("/api/v1/analyze/async", json={"domain": "example.com"}, headers=AUTH_HEADER)
        rid = r.json()["request_id"]

        # Give the background thread up to 3 s to finish.
        deadline = time.time() + 3
        while time.time() < deadline:
            status_r = client.get(f"/api/v1/status/{rid}", headers=AUTH_HEADER)
            if status_r.json().get("status") == "completed":
                break
            time.sleep(0.05)

        assert status_r.status_code == 200
        data = status_r.json()
        assert data["status"] == "completed"
        assert data["result"]["domain"] == "example.com"

    def test_requires_auth(self, client):
        r = client.get("/api/v1/status/some-id")
        assert r.status_code == 401


# ── POST /api/v1/analyze/batch ────────────────────────────────────────────────


class TestBatch:
    def test_returns_202_with_batch_id(self, client):
        with _make_mock_analyse():
            r = client.post(
                "/api/v1/analyze/batch",
                json={"domains": ["example.com", "example.org"]},
                headers=AUTH_HEADER,
            )
        assert r.status_code == 202
        data = r.json()
        assert "batch_id" in data
        assert data["total_domains"] == 2
        assert "status_url" in data

    def test_empty_domains_list_returns_422(self, client):
        r = client.post("/api/v1/analyze/batch", json={"domains": []}, headers=AUTH_HEADER)
        assert r.status_code == 422

    def test_too_many_domains_returns_422(self, client):
        domains = [f"example{i}.com" for i in range(101)]
        r = client.post("/api/v1/analyze/batch", json={"domains": domains}, headers=AUTH_HEADER)
        assert r.status_code == 422

    def test_domains_normalised(self, client):
        captured = []

        def _capture(domain, selector):
            captured.append(domain)
            return _FAKE_RESULT

        with patch("dmarc_agent.api_server._analyse_domain", side_effect=_capture):
            client.post(
                "/api/v1/analyze/batch",
                json={"domains": ["EXAMPLE.COM", "  Example.Org  "]},
                headers=AUTH_HEADER,
            )

        # Give threads time to run
        deadline = time.time() + 3
        while time.time() < deadline and len(captured) < 2:
            time.sleep(0.05)

        assert "example.com" in captured
        assert "example.org" in captured


# ── GET /api/v1/batch/{batch_id}/status ──────────────────────────────────────


class TestBatchStatus:
    def test_unknown_batch_id_returns_404(self, client):
        r = client.get("/api/v1/batch/nonexistent/status", headers=AUTH_HEADER)
        assert r.status_code == 404
        assert r.json()["error"]["code"] == "NOT_FOUND"

    def test_batch_completes_with_results(self, client):
        with _make_mock_analyse():
            r = client.post(
                "/api/v1/analyze/batch",
                json={"domains": ["example.com"]},
                headers=AUTH_HEADER,
            )
        bid = r.json()["batch_id"]

        deadline = time.time() + 3
        status_r = None
        while time.time() < deadline:
            status_r = client.get(f"/api/v1/batch/{bid}/status", headers=AUTH_HEADER)
            if status_r.json().get("status") != "processing":
                break
            time.sleep(0.05)

        assert status_r is not None
        data = status_r.json()
        assert data["status"] == "completed"
        assert data["progress"]["total"] == 1
        assert data["progress"]["completed"] == 1
        assert data["progress"]["failed"] == 0
        assert len(data["results"]) == 1
        assert data["results"][0]["domain"] == "example.com"
        assert data["results"][0]["risk_level"] == "MEDIUM"

    def test_requires_auth(self, client):
        r = client.get("/api/v1/batch/some-id/status")
        assert r.status_code == 401


# ── Rate limiting ─────────────────────────────────────────────────────────────


class TestRateLimiting:
    def test_rate_limit_enforced_on_analyze(self, client):
        from dmarc_agent import api_server  # noqa: PLC0415

        # Saturate the analyze bucket for this key
        api_server._rate_store.clear()
        api_key = TEST_API_KEY
        bucket_key = f"{api_key}:analyze"
        now = time.monotonic()
        api_server._rate_store[bucket_key] = [now] * api_server._RATE_LIMITS["analyze"]

        with _make_mock_analyse():
            r = client.post("/api/v1/analyze", json={"domain": "example.com"}, headers=AUTH_HEADER)

        assert r.status_code == 429
        assert r.json()["error"]["code"] == "RATE_LIMIT_EXCEEDED"

    def test_rate_limit_window_resets(self, client):
        from dmarc_agent import api_server  # noqa: PLC0415

        api_server._rate_store.clear()
        api_key = TEST_API_KEY
        bucket_key = f"{api_key}:analyze"
        # Add timestamps older than 60 s (outside window)
        old = time.monotonic() - 120
        api_server._rate_store[bucket_key] = [old] * api_server._RATE_LIMITS["analyze"]

        with _make_mock_analyse():
            r = client.post("/api/v1/analyze", json={"domain": "example.com"}, headers=AUTH_HEADER)

        assert r.status_code == 200
