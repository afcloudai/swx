"""
Alembic Migration: v2.31.0 Add OIDC client post-logout redirect URIs (SWX-IDM-001)
==================================================================================

Adds ``post_logout_redirect_uris`` (JSONB array, exact-match list) to
``swx_oidc_clients`` — backing the ``end_session_endpoint`` (RP-initiated
logout): a post-logout redirect is only followed when the URI is registered.

This is a standalone template revision. Copy this file into your project's
``migrations/versions/``, set ``down_revision`` to your current head, and run
``alembic upgrade head``.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "v2_31_0_oidc_post_logout_uris"
down_revision: str | None = None
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "swx_oidc_clients",
        sa.Column("post_logout_redirect_uris", postgresql.JSONB(astext_type=sa.text()), nullable=False, server_default=sa.text("'[]'::jsonb")),
    )


def downgrade() -> None:
    op.drop_column("swx_oidc_clients", "post_logout_redirect_uris")