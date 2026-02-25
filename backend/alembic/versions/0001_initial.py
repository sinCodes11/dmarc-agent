"""initial

Revision ID: 0001_initial
Revises:
Create Date: 2026-02-25 00:00:00

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision: str = "0001_initial"
down_revision: Union[str, Sequence[str], None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("email", sa.String(length=320), nullable=False),
        sa.Column("password_hash", sa.String(length=255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("reset_token", sa.String(length=255), nullable=True),
        sa.Column("reset_token_expires", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("email"),
    )
    op.create_index(op.f("ix_users_email"), "users", ["email"], unique=True)
    op.create_index(op.f("ix_users_reset_token"), "users", ["reset_token"], unique=False)

    op.create_table(
        "subscriptions",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("stripe_customer_id", sa.String(length=255), nullable=False),
        sa.Column("stripe_subscription_id", sa.String(length=255), nullable=True),
        sa.Column("plan", sa.String(length=32), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("current_period_end", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("stripe_customer_id"),
        sa.UniqueConstraint("stripe_subscription_id"),
    )
    op.create_index(op.f("ix_subscriptions_user_id"), "subscriptions", ["user_id"], unique=False)

    op.create_table(
        "domains",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("domain", sa.String(length=255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("last_scanned_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("current_risk_level", sa.String(length=32), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("user_id", "domain", name="uq_user_domain"),
    )
    op.create_index(op.f("ix_domains_user_id"), "domains", ["user_id"], unique=False)

    op.create_table(
        "scans",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("domain_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("result", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["domain_id"], ["domains.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_scans_domain_id"), "scans", ["domain_id"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_scans_domain_id"), table_name="scans")
    op.drop_table("scans")
    op.drop_index(op.f("ix_domains_user_id"), table_name="domains")
    op.drop_table("domains")
    op.drop_index(op.f("ix_subscriptions_user_id"), table_name="subscriptions")
    op.drop_table("subscriptions")
    op.drop_index(op.f("ix_users_reset_token"), table_name="users")
    op.drop_index(op.f("ix_users_email"), table_name="users")
    op.drop_table("users")
