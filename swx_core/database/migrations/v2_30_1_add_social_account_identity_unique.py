"""
Alembic Migration: v2.30.1 Unique identity index on swx_social_accounts (SWX-IDM-001)
=====================================================================================

One external identity must map to exactly one user account: adds a unique
index over (provider, provider_id) so an IdP subject (idp_sub) can never be
claimed twice — the invariant the OIDC account-linking helper relies on.

FAIL-CLOSED: the migration aborts if historical duplicate rows exist.
Resolve duplicates manually first (never silently delete identity links).

This is a standalone template revision. Copy this file into your project's
``migrations/versions/``, set ``down_revision`` to your current head, and run
``alembic upgrade head``.
"""

from collections.abc import Sequence

from alembic import op

revision: str = "v2_30_1_social_account_identity_unique"
down_revision: str | None = None
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