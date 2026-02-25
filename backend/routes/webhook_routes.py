from __future__ import annotations

import os
import random
import string
from datetime import datetime, timezone

import stripe
from fastapi import APIRouter, Depends, Header, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.auth import hash_password
from backend.database import get_db
from backend.db_models import Domain, Scan, Subscription, User
from backend.emailer import EmailConfigError, send_html_email
from backend.scanner import run_scan

router = APIRouter(tags=["webhooks"])

stripe.api_key = os.getenv("STRIPE_SECRET_KEY", "")
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET", "")
APP_BASE_URL = os.getenv("APP_BASE_URL", "https://sentrydmarc.com")

PRICE_TO_PLAN = {
    os.getenv("STRIPE_PRICE_STARTER_MONTHLY", ""): "starter",
    os.getenv("STRIPE_PRICE_STARTER_ANNUAL", ""): "starter",
    os.getenv("STRIPE_PRICE_GROWTH_MONTHLY", ""): "growth",
    os.getenv("STRIPE_PRICE_GROWTH_ANNUAL", ""): "growth",
    os.getenv("STRIPE_PRICE_BUSINESS_MONTHLY", ""): "business",
    os.getenv("STRIPE_PRICE_BUSINESS_ANNUAL", ""): "business",
}
PRICE_TO_PLAN = {k: v for k, v in PRICE_TO_PLAN.items() if k}


def _generate_temp_password(length: int = 12) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(random.SystemRandom().choice(alphabet) for _ in range(length))


def _as_datetime(value: int | None) -> datetime | None:
    if not value:
        return None
    return datetime.fromtimestamp(value, tz=timezone.utc)


async def _upsert_subscription(
    db: AsyncSession,
    user: User,
    stripe_customer_id: str,
    stripe_subscription_id: str | None,
    plan: str,
    status: str = "active",
    current_period_end: datetime | None = None,
) -> Subscription:
    existing_result = await db.execute(select(Subscription).where(Subscription.user_id == user.id))
    subscription = existing_result.scalar_one_or_none()

    if not subscription:
        subscription = Subscription(
            user_id=user.id,
            stripe_customer_id=stripe_customer_id,
            stripe_subscription_id=stripe_subscription_id,
            plan=plan,
            status=status,
            current_period_end=current_period_end,
        )
        db.add(subscription)
    else:
        subscription.stripe_customer_id = stripe_customer_id
        subscription.stripe_subscription_id = stripe_subscription_id
        subscription.plan = plan
        subscription.status = status
        subscription.current_period_end = current_period_end

    return subscription


async def _auto_add_domain_and_scan(db: AsyncSession, user: User, domain_name: str) -> None:
    cleaned = domain_name.strip().lower()
    if not cleaned:
        return

    existing = await db.execute(select(Domain).where(Domain.user_id == user.id, Domain.domain == cleaned))
    domain_row = existing.scalar_one_or_none()
    if not domain_row:
        domain_row = Domain(user_id=user.id, domain=cleaned)
        db.add(domain_row)
        await db.flush()

    result = run_scan(cleaned)
    risk_level = str(result.get("risk_level", "UNKNOWN")).upper()

    db.add(Scan(domain_id=domain_row.id, result=result))
    domain_row.current_risk_level = risk_level
    domain_row.last_scanned_at = datetime.now(timezone.utc)


@router.post("/webhooks/stripe")
async def stripe_webhook(
    request: Request,
    stripe_signature: str | None = Header(default=None, alias="stripe-signature"),
    db: AsyncSession = Depends(get_db),
) -> dict:
    if not stripe.api_key:
        raise HTTPException(status_code=500, detail="Stripe is not configured")
    if not STRIPE_WEBHOOK_SECRET:
        raise HTTPException(status_code=500, detail="STRIPE_WEBHOOK_SECRET is not configured")
    if not stripe_signature:
        raise HTTPException(status_code=400, detail="Missing stripe-signature header")

    body = await request.body()
    try:
        event = stripe.Webhook.construct_event(body, stripe_signature, STRIPE_WEBHOOK_SECRET)
    except (ValueError, stripe.error.SignatureVerificationError) as exc:
        raise HTTPException(status_code=400, detail=f"Invalid webhook payload: {exc}") from exc

    event_type = event.get("type")
    data_object = event.get("data", {}).get("object", {})

    if event_type == "checkout.session.completed":
        session_id = data_object.get("id")
        session = stripe.checkout.Session.retrieve(session_id, expand=["line_items"])

        email = session.get("customer_email") or (session.get("customer_details") or {}).get("email")
        if not email:
            return {"status": "ok"}

        metadata = session.get("metadata") or {}
        domain_name = metadata.get("domain", "")

        line_items = session.get("line_items", {}).get("data", [])
        price_id = ""
        if line_items:
            price_id = ((line_items[0] or {}).get("price") or {}).get("id", "")

        plan = PRICE_TO_PLAN.get(price_id, "starter")
        customer_id = session.get("customer", "")
        subscription_id = session.get("subscription")

        user_result = await db.execute(select(User).where(User.email == email.lower()))
        user = user_result.scalar_one_or_none()

        temp_password = None
        created_new_user = False
        if not user:
            temp_password = _generate_temp_password(12)
            user = User(email=email.lower(), password_hash=hash_password(temp_password))
            db.add(user)
            await db.flush()
            created_new_user = True

        await _upsert_subscription(
            db=db,
            user=user,
            stripe_customer_id=customer_id,
            stripe_subscription_id=subscription_id,
            plan=plan,
            status="active",
        )

        if domain_name:
            await _auto_add_domain_and_scan(db, user, domain_name)

        await db.commit()

        if created_new_user and temp_password:
            domain_line = f"<p>We've started your first scan of <strong>{domain_name}</strong>.</p>" if domain_name else ""
            html = (
                "<p>Your account has been created.</p>"
                f"<p>Email: <strong>{email}</strong><br/>"
                f"Temporary password: <strong>{temp_password}</strong></p>"
                f"<p><a href=\"{APP_BASE_URL}/login\" "
                "style=\"display:inline-block;padding:10px 18px;background:#3b82f6;color:#fff;text-decoration:none;border-radius:8px;font-weight:600;\">"
                "Log in to SentryDMARC</a></p>"
                "<p>Change your password in Settings after logging in.</p>"
                f"{domain_line}"
            )
            try:
                send_html_email(
                    to_email=email,
                    subject="Welcome to SentryDMARC — your account is ready",
                    html=html,
                    text=(
                        f"Your account has been created. Email: {email}. "
                        f"Temporary password: {temp_password}. Log in: {APP_BASE_URL}/login"
                    ),
                )
            except EmailConfigError:
                pass

        return {"status": "ok"}

    if event_type == "customer.subscription.updated":
        sub_id = data_object.get("id")
        status = data_object.get("status", "active")
        current_period_end = _as_datetime(data_object.get("current_period_end"))

        plan = "starter"
        items = (data_object.get("items") or {}).get("data", [])
        if items:
            price_id = ((items[0] or {}).get("price") or {}).get("id", "")
            plan = PRICE_TO_PLAN.get(price_id, "starter")

        result = await db.execute(select(Subscription).where(Subscription.stripe_subscription_id == sub_id))
        subscription = result.scalar_one_or_none()
        if subscription:
            subscription.status = status
            subscription.plan = plan
            subscription.current_period_end = current_period_end
            await db.commit()

        return {"status": "ok"}

    if event_type == "customer.subscription.deleted":
        sub_id = data_object.get("id")
        result = await db.execute(select(Subscription).where(Subscription.stripe_subscription_id == sub_id))
        subscription = result.scalar_one_or_none()
        if subscription:
            subscription.status = "cancelled"
            await db.commit()

        return {"status": "ok"}

    return {"status": "ignored"}
