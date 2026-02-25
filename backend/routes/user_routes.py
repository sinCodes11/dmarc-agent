from __future__ import annotations

import os
import re
import uuid
from datetime import datetime, timezone

import stripe
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.auth import get_current_user, hash_password, verify_password
from backend.database import get_db
from backend.db_models import Domain, Scan, Subscription, User
from backend.scanner import run_scan

PLAN_DOMAIN_LIMITS = {"starter": 1, "growth": 5, "business": 15}
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$")

stripe.api_key = os.getenv("STRIPE_SECRET_KEY", "")
APP_BASE_URL = os.getenv("APP_BASE_URL", "https://sentrydmarc.com")

router = APIRouter(tags=["user"])


class CreateDomainRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    domain: str = Field(min_length=3)


class ChangePasswordRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    current_password: str
    new_password: str = Field(min_length=8)


def _extract_risk_level(scan_result: dict) -> str:
    return str(scan_result.get("risk_level", "UNKNOWN")).upper()


def _validate_domain_name(domain: str) -> str:
    cleaned = domain.strip().lower()
    if not DOMAIN_RE.match(cleaned):
        raise HTTPException(status_code=400, detail="Invalid domain format")
    return cleaned


async def _get_subscription(db: AsyncSession, user_id: uuid.UUID) -> Subscription | None:
    result = await db.execute(select(Subscription).where(Subscription.user_id == user_id))
    return result.scalar_one_or_none()


async def _get_domain_for_user(db: AsyncSession, user_id: uuid.UUID, domain_id: str) -> Domain:
    try:
        parsed_id = uuid.UUID(domain_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail="Domain not found") from exc

    result = await db.execute(select(Domain).where(Domain.id == parsed_id, Domain.user_id == user_id))
    domain = result.scalar_one_or_none()
    if not domain:
        raise HTTPException(status_code=404, detail="Domain not found")
    return domain


@router.get("/api/user")
async def get_user_profile(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    subscription = await _get_subscription(db, current_user.id)
    return {
        "id": str(current_user.id),
        "email": current_user.email,
        "plan": subscription.plan if subscription else "starter",
        "subscription_status": subscription.status if subscription else "inactive",
        "current_period_end": subscription.current_period_end.isoformat() if subscription and subscription.current_period_end else None,
    }


@router.get("/api/user/domains")
async def list_domains(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> list[dict]:
    result = await db.execute(
        select(Domain)
        .where(Domain.user_id == current_user.id)
        .order_by(desc(Domain.created_at))
    )
    domains = result.scalars().all()
    return [
        {
            "id": str(domain.id),
            "domain": domain.domain,
            "current_risk_level": domain.current_risk_level,
            "last_scanned_at": domain.last_scanned_at.isoformat() if domain.last_scanned_at else None,
        }
        for domain in domains
    ]


@router.post("/api/user/domains")
async def add_domain(
    payload: CreateDomainRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    domain_name = _validate_domain_name(payload.domain)

    subscription = await _get_subscription(db, current_user.id)
    plan = subscription.plan if subscription else "starter"
    limit = PLAN_DOMAIN_LIMITS.get(plan, PLAN_DOMAIN_LIMITS["starter"])

    count_result = await db.execute(select(func.count(Domain.id)).where(Domain.user_id == current_user.id))
    domain_count = int(count_result.scalar_one() or 0)
    if domain_count >= limit:
        raise HTTPException(status_code=403, detail="Upgrade to add more domains")

    dup_result = await db.execute(select(Domain).where(Domain.user_id == current_user.id, Domain.domain == domain_name))
    if dup_result.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="Domain already added")

    domain_row = Domain(user_id=current_user.id, domain=domain_name)
    db.add(domain_row)
    await db.flush()

    scan_result = run_scan(domain_name)
    risk_level = _extract_risk_level(scan_result)

    scan_row = Scan(domain_id=domain_row.id, result=scan_result)
    db.add(scan_row)

    domain_row.current_risk_level = risk_level
    domain_row.last_scanned_at = datetime.now(timezone.utc)

    await db.commit()
    await db.refresh(domain_row)

    return {
        "id": str(domain_row.id),
        "domain": domain_row.domain,
        "current_risk_level": domain_row.current_risk_level,
        "scan_result": scan_result,
    }


@router.delete("/api/user/domains/{domain_id}")
async def delete_domain(
    domain_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    domain = await _get_domain_for_user(db, current_user.id, domain_id)
    await db.delete(domain)
    await db.commit()
    return {"success": True}


@router.get("/api/user/domains/{domain_id}")
async def get_domain_details(
    domain_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    domain = await _get_domain_for_user(db, current_user.id, domain_id)

    latest_scan_result = await db.execute(
        select(Scan).where(Scan.domain_id == domain.id).order_by(desc(Scan.created_at)).limit(1)
    )
    latest_scan = latest_scan_result.scalar_one_or_none()

    return {
        "id": str(domain.id),
        "domain": domain.domain,
        "current_risk_level": domain.current_risk_level,
        "last_scanned_at": domain.last_scanned_at.isoformat() if domain.last_scanned_at else None,
        "latest_scan_result": latest_scan.result if latest_scan else None,
    }


@router.get("/api/user/domains/{domain_id}/scans")
async def list_domain_scans(
    domain_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> list[dict]:
    domain = await _get_domain_for_user(db, current_user.id, domain_id)

    scans_result = await db.execute(
        select(Scan).where(Scan.domain_id == domain.id).order_by(desc(Scan.created_at)).limit(10)
    )
    scans = scans_result.scalars().all()

    return [
        {
            "id": str(scan.id),
            "created_at": scan.created_at.isoformat() if scan.created_at else None,
            "risk_level": _extract_risk_level(scan.result),
        }
        for scan in scans
    ]


@router.post("/api/user/domains/{domain_id}/scan")
async def run_domain_scan(
    domain_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    domain = await _get_domain_for_user(db, current_user.id, domain_id)

    result = run_scan(domain.domain)
    risk_level = _extract_risk_level(result)

    scan = Scan(domain_id=domain.id, result=result)
    db.add(scan)

    domain.current_risk_level = risk_level
    domain.last_scanned_at = datetime.now(timezone.utc)

    await db.commit()
    await db.refresh(scan)

    return {
        "scan_id": str(scan.id),
        "result": result,
        "risk_level": risk_level,
    }


@router.post("/api/billing/portal")
async def create_billing_portal(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    subscription = await _get_subscription(db, current_user.id)
    if not subscription or not subscription.stripe_customer_id:
        raise HTTPException(status_code=404, detail="No active subscription found")
    if not stripe.api_key:
        raise HTTPException(status_code=500, detail="Stripe is not configured")

    try:
        session = stripe.billing_portal.Session.create(
            customer=subscription.stripe_customer_id,
            return_url=f"{APP_BASE_URL}/settings",
        )
    except stripe.StripeError as exc:
        raise HTTPException(status_code=502, detail=f"Failed to create billing portal: {exc}") from exc

    return {"portal_url": session.url}


@router.post("/api/user/password")
async def change_password(
    payload: ChangePasswordRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    if not verify_password(payload.current_password, current_user.password_hash):
        raise HTTPException(status_code=401, detail="Current password is incorrect")

    current_user.password_hash = hash_password(payload.new_password)
    await db.commit()
    return {"success": True}
