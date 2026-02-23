from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from datetime import datetime, timezone

_BASE = "https://api.hubapi.com"
_stage_cache: dict[str, str] = {}


def _headers() -> dict[str, str]:
    return {
        "Authorization": f"Bearer {os.getenv('HUBSPOT_API_KEY', '')}",
        "Content-Type": "application/json",
    }


def _http(method: str, path: str, body: dict | None = None) -> dict:
    url = f"{_BASE}{path}"
    if body is not None:
        data = json.dumps(body).encode()
    elif method in ("PUT", "PATCH", "DELETE"):
        data = b""
    else:
        data = None
    req = urllib.request.Request(url, data=data, headers=_headers(), method=method)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            raw = resp.read()
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode()
        raise RuntimeError(f"HubSpot {exc.code}: {detail}") from exc


def _scan_completed_stage_id() -> str:
    if "stage_id" in _stage_cache:
        return _stage_cache["stage_id"]
    resp = _http("GET", "/crm/v3/pipelines/deals")
    for pipeline in resp.get("results", []):
        for stage in pipeline.get("stages", []):
            if "scan completed" in stage.get("label", "").lower():
                _stage_cache["stage_id"] = stage["id"]
                return stage["id"]
    # fallback: first stage of first pipeline
    for pipeline in resp.get("results", []):
        stages = pipeline.get("stages", [])
        if stages:
            sid = stages[0]["id"]
            _stage_cache["stage_id"] = sid
            return sid
    return ""


def _upsert_contact(email: str, company: str, domain: str, scan_result: dict) -> str:
    security_status = scan_result.get("security_status", {})
    spf = security_status.get("spf", {})
    dmarc = security_status.get("dmarc", {})
    dkim = security_status.get("dkim", {})

    dmarc_policy = dmarc.get("policy") or ("absent" if not dmarc.get("present") else "none")

    properties = {
        "email": email,
        "company": company,
        "domain_scanned": domain,
        "dmarc_risk_level": scan_result.get("risk_level", "UNKNOWN"),
        "spf_status": "Present" if spf.get("present") else "Absent",
        "dmarc_policy": dmarc_policy,
        "dkim_status": "Present" if dkim.get("present") else "Not Detected",
        "scan_date": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        "lead_source_detail": "Organic Scan",
    }

    search = _http("POST", "/crm/v3/objects/contacts/search", {
        "filterGroups": [{"filters": [
            {"propertyName": "email", "operator": "EQ", "value": email}
        ]}],
        "properties": ["email"],
        "limit": 1,
    })

    if search.get("total", 0) > 0:
        contact_id = search["results"][0]["id"]
        _http("PATCH", f"/crm/v3/objects/contacts/{contact_id}", {"properties": properties})
        return contact_id

    resp = _http("POST", "/crm/v3/objects/contacts", {"properties": properties})
    return resp["id"]


def _create_deal(domain: str, stage_id: str) -> str:
    resp = _http("POST", "/crm/v3/objects/deals", {"properties": {
        "dealname": f"DMARC Scan — {domain}",
        "dealstage": stage_id,
        "pipeline": "default",
    }})
    return resp["id"]


def _associate_deal_contact(deal_id: str, contact_id: str) -> None:
    _http(
        "PUT",
        f"/crm/v3/objects/deals/{deal_id}/associations/contacts/{contact_id}/deal_to_contact",
    )


def push_lead(email: str, company: str, domain: str, scan_result: dict) -> None:
    """Push a scan lead to HubSpot. Silently skips if not configured."""
    if not os.getenv("HUBSPOT_API_KEY"):
        return
    try:
        stage_id = _scan_completed_stage_id()
        contact_id = _upsert_contact(email, company, domain, scan_result)
        deal_id = _create_deal(domain, stage_id)
        _associate_deal_contact(deal_id, contact_id)
    except Exception as exc:
        print(f"[HubSpot] push_lead failed: {exc}")
