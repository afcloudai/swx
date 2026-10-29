"""add user phone verification columns (SWX-IDM-001)

Revision ID: e6f8a0b2c4d6
Revises: c4d6e8f0a2b4
Create Date: 2026-10-24 00:00:00.000000

Adds phone (E.164, nullable, indexed) and phone_verified_at to swx_users —
the state gating the OIDC phone_verified claim. Additive and phone-first.
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "e6f8a0b2c4d6"
down_revision: str | None = "c4d6e8f0a2b4"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("swx_users", sa.Column("phone", sa.String(32), nullable=True))
    op.create_index("ix_swx_users_phone", "swx_users", ["phone"])
    op.add_column("swx_users", sa.Column("phone_verified_at", sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    op.drop_column("swx_users", "phone_verified_at")
    op.drop_index("ix_swx_users_phone", table_name="swx_users")
    op.drop_column("swx_users", "phone")