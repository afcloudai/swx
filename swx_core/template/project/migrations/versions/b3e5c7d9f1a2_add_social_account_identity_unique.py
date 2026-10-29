"""add unique identity index to swx_social_accounts (SWX-IDM-001)

Revision ID: b3e5c7d9f1a2
Revises: d7f1a9c4b6e8
Create Date: 2026-10-24 00:00:00.000000

One external identity must map to exactly one user account: unique index over
(provider, provider_id) — the invariant the OIDC account-linking helper relies
on. Fails closed if historical duplicates exist; resolve manually first.
"""

from collections.abc import Sequence

from alembic import op


revision: str = "b3e5c7d9f1a2"
down_revision: str | None = "d7f1a9c4b6e8"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.create_index(
        "uq_social_account_provider_identity",
        "swx_social_accounts",
        ["provider", "provider_id"],
        unique=True,
    )


def downgrade() -> None:
    op.drop_index("uq_social_account_provider_identity", table_name="swx_social_accounts")