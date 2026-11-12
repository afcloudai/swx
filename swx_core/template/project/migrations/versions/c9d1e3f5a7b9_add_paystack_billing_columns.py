"""add Paystack billing columns (SWX-IDM-001 P3)

Revision ID: c9d1e3f5a7b9
Revises: a8b0d2e4f6a8
Create Date: 2026-11-03 00:00:00.000000

paystack_plan_code + billing_environment (plan), paystack_customer_code (account),
paystack_subscription_code + paystack_email_token + managed_by (subscription).
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = "c9d1e3f5a7b9"
down_revision: str | None = "a8b0d2e4f6a8"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("swx_billing_plan", sa.Column("paystack_plan_code", sa.String(255), nullable=True))
    op.create_index("ix_swx_billing_plan_paystack_code", "swx_billing_plan", ["paystack_plan_code"])
    op.add_column("swx_billing_plan", sa.Column("billing_environment", sa.String(16), nullable=True))
    op.create_index(
        "uq_swx_billing_plan_key_environment", "swx_billing_plan",
        ["key", "billing_environment"], unique=True,
        postgresql_where=sa.text("billing_environment IS NOT NULL"),
    )
    op.add_column("swx_billing_account", sa.Column("paystack_customer_code", sa.String(255), nullable=True))
    op.create_index(
        "uq_swx_billing_account_paystack_customer", "swx_billing_account",
        ["paystack_customer_code"], unique=True,
        postgresql_where=sa.text("paystack_customer_code IS NOT NULL"),
    )
    op.add_column("swx_billing_subscription", sa.Column("paystack_subscription_code", sa.String(255), nullable=True))
    op.create_index(
        "uq_swx_billing_subscription_paystack_code", "swx_billing_subscription",
        ["paystack_subscription_code"], unique=True,
        postgresql_where=sa.text("paystack_subscription_code IS NOT NULL"),
    )
    op.add_column("swx_billing_subscription", sa.Column("paystack_email_token", sa.String(255), nullable=True))
    op.add_column("swx_billing_subscription", sa.Column("managed_by", sa.String(32), nullable=False, server_default=sa.text("'internal'")))


def downgrade() -> None:
    op.drop_column("swx_billing_subscription", "managed_by")
    op.drop_column("swx_billing_subscription", "paystack_email_token")
    op.drop_index("uq_swx_billing_subscription_paystack_code", table_name="swx_billing_subscription")
    op.drop_column("swx_billing_subscription", "paystack_subscription_code")
    op.drop_index("uq_swx_billing_account_paystack_customer", table_name="swx_billing_account")
    op.drop_column("swx_billing_account", "paystack_customer_code")
    op.drop_index("uq_swx_billing_plan_key_environment", table_name="swx_billing_plan")
    op.drop_column("swx_billing_plan", "billing_environment")
    op.drop_index("ix_swx_billing_plan_paystack_code", table_name="swx_billing_plan")
    op.drop_column("swx_billing_plan", "paystack_plan_code")
