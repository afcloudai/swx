"""
Alembic Migration: v2.22.19 Add environment to swx_api_key

Adds ``environment`` (test|live, default 'live') to ``swx_api_key`` for
Stripe-style key separation. Copy this file into your project's
``migrations/versions/``, set ``down_revision`` to your current head, and
run ``alembic upgrade head``.

Revision: v2_22_19_add_api_key_environment
Replaces: None (standalone template — wire down_revision in your project)
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "v2_22_19_add_api_key_environment"
down_revision: str | None = None
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "swx_api_key",
        sa.Column(
            "environment",
            sa.String(10),
            nullable=False,
            server_default="live",
        ),
    )
    op.create_index(
        "ix_swx_api_key_environment",
        "swx_api_key",
        ["environment"],
    )
    # Optional CHECK constraint (comment out if you prefer app-level only):
    op.create_check_constraint(
        "ck_api_key_environment",
        "swx_api_key",
        "environment IN ('test', 'live')",
    )


def downgrade() -> None:
    op.drop_constraint("ck_api_key_environment", "swx_api_key", type_="check")
    op.drop_index("ix_swx_api_key_environment", table_name="swx_api_key")
    op.drop_column("swx_api_key", "environment")