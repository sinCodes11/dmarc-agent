"""REST API server for n8n automation integration.

Exposes the dmarc-agent analysis pipeline over HTTP so that n8n workflows
can trigger single-domain and batch analyses, receive results, and route
alerts to notification channels.

Endpoints:
  GET  /api/v1/health
  POST /api/v1/analyze               — synchronous single-domain analysis
  POST /api/v1/analyze/async         — async single-domain (returns request_id)
  POST /api/v1/analyze/batch         — async batch (returns batch_id)
  GET  /api/v1/status/{request_id}   — status of an async single job
  GET  /api/v1/batch/{batch_id}/status — status of a batch job

Authentication:
  Authorization: Bearer <DMARC_API_KEY env var>

Rate limits (per API key, sliding 60-second window):
  /analyze:       10 requests / minute
  /analyze/batch: 5 requests  / minute
  /status:        60 requests / minute
"""

import json
import os
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from typing import Optional

from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, field_validator

from .cli import _run_full_analysis
from .dns_fetcher import create_fetcher
from .exceptions import DmarcAgentError, InvalidDomainError
from .report_json import JsonReporter


# ── App ────────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="DMARC Security Agent API",
    description="Email authentication analysis for SPF, DKIM, and DMARC.",
    version="0.1.0",
    docs_url="/docs",
    openapi_url="/openapi.json",
)

_reporter = JsonReporter()


# ── Request / Response models ──────────────────────────────────────────────────

class AnalyzeOptions(BaseModel):
    dkim_selector: Optional[str] = None
    report_format: str = "json"
    callback_url: Optional[str] = None


class AnalyzeRequest(BaseModel):
    domain: str
    options: AnalyzeOptions = AnalyzeOptions()

    @field_validator("domain")
    @classmethod
    def domain_not_empty(cls, v: str) -> str:
        v = v.strip().lower()
        if not v:
            raise ValueError("domain must not be empty")
        return v


class BatchRequest(BaseModel):
    domains: list[str]
    options: AnalyzeOptions = AnalyzeOptions()

    @field_validator("domains")
    @classmethod
    def domains_not_empty(cls, v: list[str]) -> list[str]:
        if not v:
            raise ValueError("domains list must not be empty")
        if len(v) > 100:
            raise ValueError("maximum 100 domains per batch")
        return [d.strip().lower() for d in v]


# ── In-memory job stores ───────────────────────────────────────────────────────

_jobs: dict[str, dict] = {}          # request_id → job state
_batches: dict[str, dict] = {}       # batch_id   → batch state
_store_lock = threading.Lock()

_executor = ThreadPoolExecutor(max_workers=8, thread_name_prefix="dmarc-worker")


# ── Rate limiting (sliding 60-second window, per API key) ─────────────────────

_rate_store: dict[str, list[float]] = {}
_rate_lock = threading.Lock()

_RATE_LIMITS = {
    "analyze": 10,
    "batch": 5,
    "status": 60,
}


def _check_rate_limit(api_key: str, bucket: str) -> bool:
    """Return True if the request is within limit, False if exceeded."""
    limit = _RATE_LIMITS.get(bucket, 10)
    now = time.monotonic()
    window_start = now - 60.0
    key = f"{api_key}:{bucket}"
    with _rate_lock:
        timestamps = _rate_store.get(key, [])
        timestamps = [t for t in timestamps if t > window_start]
        if len(timestamps) >= limit:
            _rate_store[key] = timestamps
            return False
        timestamps.append(now)
        _rate_store[key] = timestamps
        return True


# ── Auth ───────────────────────────────────────────────────────────────────────

_bearer = HTTPBearer(auto_error=False)


def _get_api_key() -> str:
    key = os.environ.get("DMARC_API_KEY", "")
    if not key:
        raise RuntimeError("DMARC_API_KEY environment variable is not set")
    return key


def _require_auth(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(_bearer),
) -> str:
    """Validate Bearer token; return the API key on success."""
    expected = _get_api_key()
    if credentials is None or credentials.credentials != expected:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": {"code": "AUTH_FAILED", "message": "Invalid or missing API key"}},
        )
    return credentials.credentials


# ── Error helpers ──────────────────────────────────────────────────────────────

def _error_response(code: str, message: str, http_status: int, request_id: str = "") -> JSONResponse:
    body = {
        "error": {
            "code": code,
            "message": message,
            "request_id": request_id or str(uuid.uuid4()),
            "timestamp": datetime.utcnow().isoformat() + "Z",
        }
    }
    return JSONResponse(status_code=http_status, content=body)


# ── Analysis helpers ───────────────────────────────────────────────────────────

def _analyse_domain(domain: str, dkim_selector: Optional[str]) -> dict:
    """Run the full analysis pipeline and return a JSON-serialisable dict."""
    fetcher = create_fetcher()
    result = _run_full_analysis(domain, dkim_selector, fetcher)
    return json.loads(_reporter.render(result))


def _run_single_async(request_id: str, domain: str, dkim_selector: Optional[str]) -> None:
    """Background worker: runs one analysis and stores the result."""
    with _store_lock:
        _jobs[request_id]["status"] = "processing"
    try:
        data = _analyse_domain(domain, dkim_selector)
        with _store_lock:
            _jobs[request_id].update({"status": "completed", "result": data, "completed_at": datetime.utcnow().isoformat() + "Z"})
    except (InvalidDomainError, DmarcAgentError) as exc:
        with _store_lock:
            _jobs[request_id].update({"status": "failed", "error": str(exc)})
    except Exception as exc:  # noqa: BLE001
        with _store_lock:
            _jobs[request_id].update({"status": "failed", "error": "Internal processing error"})


def _run_batch(batch_id: str, domains: list[str], dkim_selector: Optional[str]) -> None:
    """Background worker: analyses all domains in a batch sequentially."""
    for domain in domains:
        try:
            data = _analyse_domain(domain, dkim_selector)
            with _store_lock:
                _batches[batch_id]["results"].append({
                    "domain": domain, "status": "completed",
                    "risk_level": data.get("risk_level"), "analysis": data,
                })
                _batches[batch_id]["completed"] += 1
        except (InvalidDomainError, DmarcAgentError) as exc:
            with _store_lock:
                _batches[batch_id]["results"].append({
                    "domain": domain, "status": "failed", "error": str(exc),
                })
                _batches[batch_id]["failed"] += 1
        except Exception:  # noqa: BLE001
            with _store_lock:
                _batches[batch_id]["results"].append({
                    "domain": domain, "status": "failed", "error": "Internal processing error",
                })
                _batches[batch_id]["failed"] += 1

    with _store_lock:
        batch = _batches[batch_id]
        batch["status"] = "partial_failure" if batch["failed"] else "completed"
        batch["completed_at"] = datetime.utcnow().isoformat() + "Z"


# ── Routes ─────────────────────────────────────────────────────────────────────

@app.get("/api/v1/health", tags=["system"])
def health() -> dict:
    """Returns service health. No authentication required."""
    return {"status": "ok", "timestamp": datetime.utcnow().isoformat() + "Z", "version": "0.1.0"}


@app.post("/api/v1/analyze", tags=["analysis"])
def analyze_sync(
    body: AnalyzeRequest,
    api_key: str = Depends(_require_auth),
) -> JSONResponse:
    """Synchronous single-domain analysis. Blocks until complete (≤ 30 s)."""
    request_id = str(uuid.uuid4())

    if not _check_rate_limit(api_key, "analyze"):
        return _error_response("RATE_LIMIT_EXCEEDED", "Too many requests. Retry after 60 seconds.", 429, request_id)

    domain = body.domain
    selector = body.options.dkim_selector

    try:
        data = _analyse_domain(domain, selector)
    except InvalidDomainError as exc:
        return _error_response("INVALID_DOMAIN", str(exc), 400, request_id)
    except DmarcAgentError as exc:
        return _error_response("DNS_TIMEOUT", str(exc), 503, request_id)
    except Exception:  # noqa: BLE001
        return _error_response("INTERNAL_ERROR", "Analysis failed. Please retry.", 500, request_id)

    return JSONResponse(status_code=200, content={"request_id": request_id, **data})


@app.post("/api/v1/analyze/async", tags=["analysis"])
def analyze_async(
    body: AnalyzeRequest,
    api_key: str = Depends(_require_auth),
) -> JSONResponse:
    """Async single-domain analysis. Returns immediately with a request_id."""
    request_id = str(uuid.uuid4())

    if not _check_rate_limit(api_key, "analyze"):
        return _error_response("RATE_LIMIT_EXCEEDED", "Too many requests. Retry after 60 seconds.", 429, request_id)

    domain = body.domain
    selector = body.options.dkim_selector

    with _store_lock:
        _jobs[request_id] = {
            "request_id": request_id,
            "domain": domain,
            "status": "queued",
            "created_at": datetime.utcnow().isoformat() + "Z",
            "result": None,
            "error": None,
        }

    _executor.submit(_run_single_async, request_id, domain, selector)

    return JSONResponse(status_code=202, content={
        "request_id": request_id,
        "status": "queued",
        "status_url": f"/api/v1/status/{request_id}",
    })


@app.post("/api/v1/analyze/batch", tags=["analysis"])
def analyze_batch(
    body: BatchRequest,
    api_key: str = Depends(_require_auth),
) -> JSONResponse:
    """Async batch analysis. Returns a batch_id for polling."""
    batch_id = str(uuid.uuid4())

    if not _check_rate_limit(api_key, "batch"):
        return _error_response("RATE_LIMIT_EXCEEDED", "Batch rate limit reached. Retry after 60 seconds.", 429, batch_id)

    domains = body.domains
    selector = body.options.dkim_selector

    with _store_lock:
        _batches[batch_id] = {
            "batch_id": batch_id,
            "status": "processing",
            "total": len(domains),
            "completed": 0,
            "failed": 0,
            "created_at": datetime.utcnow().isoformat() + "Z",
            "completed_at": None,
            "results": [],
        }

    _executor.submit(_run_batch, batch_id, domains, selector)

    return JSONResponse(status_code=202, content={
        "batch_id": batch_id,
        "status": "processing",
        "total_domains": len(domains),
        "status_url": f"/api/v1/batch/{batch_id}/status",
    })


@app.get("/api/v1/status/{request_id}", tags=["analysis"])
def job_status(
    request_id: str,
    api_key: str = Depends(_require_auth),
) -> JSONResponse:
    """Poll the status of an async single-domain analysis."""
    if not _check_rate_limit(api_key, "status"):
        return _error_response("RATE_LIMIT_EXCEEDED", "Status poll rate limit reached.", 429, request_id)

    with _store_lock:
        job = _jobs.get(request_id)

    if job is None:
        return _error_response("NOT_FOUND", f"No job with id {request_id}", 404, request_id)

    return JSONResponse(status_code=200, content=job)


@app.get("/api/v1/batch/{batch_id}/status", tags=["analysis"])
def batch_status(
    batch_id: str,
    api_key: str = Depends(_require_auth),
) -> JSONResponse:
    """Poll the status and partial results of a batch analysis."""
    if not _check_rate_limit(api_key, "status"):
        return _error_response("RATE_LIMIT_EXCEEDED", "Status poll rate limit reached.", 429, batch_id)

    with _store_lock:
        batch = _batches.get(batch_id)

    if batch is None:
        return _error_response("NOT_FOUND", f"No batch with id {batch_id}", 404, batch_id)

    return JSONResponse(status_code=200, content={
        **batch,
        "progress": {
            "total": batch["total"],
            "completed": batch["completed"],
            "failed": batch["failed"],
            "pending": batch["total"] - batch["completed"] - batch["failed"],
        },
    })


# ── Global exception handlers ──────────────────────────────────────────────────

@app.exception_handler(HTTPException)
async def _http_exc(request: Request, exc: HTTPException) -> JSONResponse:
    """Reformat HTTPException so auth errors use our standard error envelope."""
    if isinstance(exc.detail, dict):
        return JSONResponse(status_code=exc.status_code, content=exc.detail)
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": {"code": "HTTP_ERROR", "message": str(exc.detail)}},
    )


@app.exception_handler(Exception)
async def _unhandled(request: Request, exc: Exception) -> JSONResponse:
    return _error_response("INTERNAL_ERROR", "An unexpected error occurred.", 500)
