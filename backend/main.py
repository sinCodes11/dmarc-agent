from __future__ import annotations

import os
import time
import uuid
from pathlib import Path
from typing import Any

import stripe
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from backend.emailer import EmailConfigError, send_report
from backend.models import CheckoutRequest, CheckoutResponse, ErrorResponse, ReportRequest, ReportResponse, ScanRequest, ScanResponse
from backend.scanner import render_html_report, run_scan

load_dotenv()

stripe.api_key = os.getenv("STRIPE_SECRET_KEY", "")

APP_BASE_URL = os.getenv("APP_BASE_URL", "https://sentrydmarc.com")

_PRICE_IDS = {
    "starter": {
        "monthly": os.getenv("STRIPE_PRICE_STARTER_MONTHLY", ""),
        "annual":  os.getenv("STRIPE_PRICE_STARTER_ANNUAL", ""),
    },
    "growth": {
        "monthly": os.getenv("STRIPE_PRICE_GROWTH_MONTHLY", ""),
        "annual":  os.getenv("STRIPE_PRICE_GROWTH_ANNUAL", ""),
    },
    "business": {
        "monthly": os.getenv("STRIPE_PRICE_BUSINESS_MONTHLY", ""),
        "annual":  os.getenv("STRIPE_PRICE_BUSINESS_ANNUAL", ""),
    },
}

def _allowed_price_ids() -> set[str]:
    return {pid for tier in _PRICE_IDS.values() for pid in tier.values() if pid}

app = FastAPI(title="DMARC SaaS API", version="0.1.0")

origins_env = os.getenv("ALLOWED_ORIGINS", "*").strip()
allow_origins = [o.strip() for o in origins_env.split(",") if o.strip()] or ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allow_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

SCAN_CACHE_TTL_SECONDS = int(os.getenv("SCAN_CACHE_TTL_SECONDS", "3600"))
_SCAN_CACHE: dict[str, dict[str, Any]] = {}


class ApiError(Exception):
    def __init__(self, status_code: int, error: str, message: str, details: dict[str, Any] | None = None):
        self.status_code = status_code
        self.error = error
        self.message = message
        self.details = details


def _now() -> int:
    return int(time.time())


def _purge_expired() -> None:
    current = _now()
    stale = [scan_id for scan_id, item in _SCAN_CACHE.items() if item["expires_at"] <= current]
    for scan_id in stale:
        _SCAN_CACHE.pop(scan_id, None)


def _get_scan_or_404(scan_id: str) -> dict[str, Any]:
    _purge_expired()
    item = _SCAN_CACHE.get(scan_id)
    if not item:
        raise ApiError(404, "not_found", "Scan not found or expired", {"scan_id": scan_id})
    return item


@app.exception_handler(ApiError)
async def api_error_handler(_, exc: ApiError):
    payload = ErrorResponse(error=exc.error, message=exc.message, details=exc.details)
    return JSONResponse(status_code=exc.status_code, content=payload.model_dump())


@app.exception_handler(RequestValidationError)
async def validation_error_handler(_, exc: RequestValidationError):
    payload = ErrorResponse(
        error="validation_error",
        message="Request validation failed",
        details={"errors": exc.errors()},
    )
    return JSONResponse(status_code=422, content=payload.model_dump())


@app.exception_handler(HTTPException)
async def http_error_handler(_, exc: HTTPException):
    payload = ErrorResponse(error="http_error", message=str(exc.detail), details=None)
    return JSONResponse(status_code=exc.status_code, content=payload.model_dump())


@app.exception_handler(Exception)
async def unhandled_error_handler(_, exc: Exception):
    payload = ErrorResponse(error="internal_error", message="Unexpected server error", details={"reason": str(exc)})
    return JSONResponse(status_code=500, content=payload.model_dump())


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/api/scan", response_model=ScanResponse)
async def create_scan(req: ScanRequest):
    try:
        result_dict = run_scan(req.domain)
    except Exception as exc:
        raise ApiError(500, "scan_error", "Failed to run scan", {"reason": str(exc)})

    created_at = _now()
    expires_at = created_at + SCAN_CACHE_TTL_SECONDS
    scan_id = str(uuid.uuid4())

    payload = {
        "scan_id": scan_id,
        "created_at": created_at,
        "expires_at": expires_at,
        "result": result_dict,
    }
    _SCAN_CACHE[scan_id] = payload
    return payload


@app.get("/api/scan/{scan_id}", response_model=ScanResponse)
async def get_scan(scan_id: str):
    return _get_scan_or_404(scan_id)


@app.post("/api/scan/{scan_id}/report", response_model=ReportResponse)
async def send_scan_report(scan_id: str, req: ReportRequest):
    item = _get_scan_or_404(scan_id)
    result = item["result"]
    domain = str(result.get("domain", "unknown"))
    html_report = render_html_report(domain)

    try:
        send_report(req.email, domain, result, html_report)
    except EmailConfigError as exc:
        raise ApiError(500, "email_config_error", "Email settings are incomplete", {"reason": str(exc)})
    except Exception as exc:
        raise ApiError(502, "email_delivery_error", "Failed to send report", {"reason": str(exc)})

    return {
        "success": True,
        "message": f"Report sent to {req.email}",
    }


@app.get("/api/prices")
async def get_prices() -> dict:
    return _PRICE_IDS


@app.post("/api/checkout", response_model=CheckoutResponse)
async def create_checkout(req: CheckoutRequest):
    if not stripe.api_key:
        raise ApiError(500, "config_error", "Payment processing not configured")
    if req.price_id not in _allowed_price_ids():
        raise ApiError(400, "invalid_price", "Invalid price ID")
    try:
        session = stripe.checkout.Session.create(
            mode="subscription",
            line_items=[{"price": req.price_id, "quantity": 1}],
            success_url=f"{APP_BASE_URL}/success?session_id={{CHECKOUT_SESSION_ID}}",
            cancel_url=f"{APP_BASE_URL}/pricing",
            customer_email=str(req.email) if req.email else None,
            metadata={"domain": req.domain or ""},
        )
    except stripe.StripeError as exc:
        raise ApiError(502, "stripe_error", "Payment session creation failed", {"reason": str(exc)})
    return {"checkout_url": session.url}


frontend_path = Path(__file__).resolve().parent.parent / "frontend"


@app.get("/pricing")
async def pricing_page():
    return FileResponse(str(frontend_path / "pricing.html"))


@app.get("/success")
async def success_page():
    return FileResponse(str(frontend_path / "success.html"))


if frontend_path.exists():
    app.mount("/", StaticFiles(directory=str(frontend_path), html=True), name="frontend")
