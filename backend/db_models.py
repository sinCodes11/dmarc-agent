from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import JSON, DateTime, ForeignKey, String, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.database import Base


class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email: Mapped[str] = mapped_column(String(320), unique=True, nullable=False, index=True)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    reset_token: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    reset_token_expires: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    subscription: Mapped["Subscription | None"] = relationship(
        "Subscription", back_populates="user", uselist=False, cascade="all, delete-orphan"
    )
    domains: Mapped[list["Domain"]] = relationship("Domain", back_populates="user", cascade="all, delete-orphan")


class Subscription(Base):
    __tablename__ = "subscriptions"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    stripe_customer_id: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    stripe_subscription_id: Mapped[str | None] = mapped_column(String(255), unique=True, nullable=True)
    plan: Mapped[str] = mapped_column(String(32), nullable=False, default="starter")
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="active")
    current_period_end: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())

    user: Mapped[User] = relationship("User", back_populates="subscription")


class Domain(Base):
    __tablename__ = "domains"
    __table_args__ = (UniqueConstraint("user_id", "domain", name="uq_user_domain"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    domain: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    last_scanned_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    current_risk_level: Mapped[str | None] = mapped_column(String(32), nullable=True)

    user: Mapped[User] = relationship("User", back_populates="domains")
    scans: Mapped[list["Scan"]] = relationship("Scan", back_populates="domain_ref", cascade="all, delete-orphan")


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    domain_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("domains.id", ondelete="CASCADE"), nullable=False, index=True
    )
    result: Mapped[dict] = mapped_column(JSON, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())

    domain_ref: Mapped[Domain] = relationship("Domain", back_populates="scans")
