"""
Alembic Migration: v2.30.3 Add user phone verification columns (SWX-IDM-001)
============================================================================

Adds ``phone`` (nullable, indexed, E.164) and ``phone_verified_at`` to
``swx_users`` — the person-level verification state gating the OIDC
``phone_verified`` claim. Email stays untouched (additive, phone-first).

This is a standalone template revision. Copy this file into your project's
``migrations/versions/``, set ``down_revision`` to your current head, and run
``alembic upgrade head``.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "v2_30_3_user_phone_verification"
down_revision: str | None = None
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