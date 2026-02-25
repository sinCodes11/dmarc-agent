from __future__ import annotations

import os
import uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, EmailStr, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.auth import create_access_token, hash_password, verify_password
from backend.database import get_db
from backend.db_models import Subscription, User
from backend.emailer import EmailConfigError, send_html_email

router = APIRouter(prefix="/auth", tags=["auth"])
APP_BASE_URL = os.getenv("APP_BASE_URL", "https://sentrydmarc.com")


class SignupRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    email: EmailStr
    password: str = Field(min_length=8)


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    email: EmailStr
    password: str


class ForgotPasswordRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    email: EmailStr


class ResetPasswordRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    token: str
    new_password: str = Field(min_length=8)


@router.post("/signup")
async def signup(payload: SignupRequest, db: AsyncSession = Depends(get_db)) -> dict:
    existing = await db.execute(select(User).where(User.email == payload.email.lower()))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="Email already registered")

    user = User(email=payload.email.lower(), password_hash=hash_password(payload.password))
    db.add(user)
    await db.commit()
    await db.refresh(user)

    token = create_access_token(str(user.id))
    return {"token": token, "user": {"id": str(user.id), "email": user.email}}


@router.post("/login")
async def login(payload: LoginRequest, db: AsyncSession = Depends(get_db)) -> dict:
    user_result = await db.execute(select(User).where(User.email == payload.email.lower()))
    user = user_result.scalar_one_or_none()
    if not user or not verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    sub_result = await db.execute(select(Subscription).where(Subscription.user_id == user.id))
    subscription = sub_result.scalar_one_or_none()
    plan = subscription.plan if subscription else "starter"

    token = create_access_token(str(user.id))
    return {
        "token": token,
        "user": {
            "id": str(user.id),
            "email": user.email,
            "plan": plan,
        },
    }


@router.post("/forgot-password")
async def forgot_password(payload: ForgotPasswordRequest, db: AsyncSession = Depends(get_db)) -> dict:
    user_result = await db.execute(select(User).where(User.email == payload.email.lower()))
    user = user_result.scalar_one_or_none()

    if user:
        token = str(uuid.uuid4())
        user.reset_token = token
        user.reset_token_expires = datetime.now(timezone.utc) + timedelta(hours=1)
        await db.commit()

        reset_link = f"{APP_BASE_URL}/reset-password?token={token}"
        html = (
            "<p>We received a password reset request for your SentryDMARC account.</p>"
            f"<p><a href=\"{reset_link}\">Reset your password</a></p>"
            "<p>This link expires in 1 hour.</p>"
        )
        try:
            send_html_email(
                to_email=user.email,
                subject="Reset your SentryDMARC password",
                html=html,
                text=f"Reset your password: {reset_link}",
            )
        except EmailConfigError:
            # Silent success to avoid leaking account details.
            pass

    return {"success": True}


@router.post("/reset-password")
async def reset_password(payload: ResetPasswordRequest, db: AsyncSession = Depends(get_db)) -> dict:
    now = datetime.now(timezone.utc)
    result = await db.execute(
        select(User).where(
            User.reset_token == payload.token,
            User.reset_token_expires.is_not(None),
            User.reset_token_expires > now,
        )
    )
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=400, detail="Invalid or expired token")

    user.password_hash = hash_password(payload.new_password)
    user.reset_token = None
    user.reset_token_expires = None
    await db.commit()

    return {"success": True}
