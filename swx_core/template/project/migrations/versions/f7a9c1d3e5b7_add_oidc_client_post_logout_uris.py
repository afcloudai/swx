"""add OIDC client post-logout redirect URIs (SWX-IDM-001)

Revision ID: f7a9c1d3e5b7
Revises: e6f8a0b2c4d6
Create Date: 2026-10-25 00:00:00.000000

Backing column for the end_session_endpoint (RP-initiated logout): post-logout
redirects are only followed when the URI is exactly registered.
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = "f7a9c1d3e5b7"
down_revision: str | None = "e6f8a0b2c4d6"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "swx_oidc_clients",
        sa.Column("post_logout_redirect_uris", postgresql.JSONB(astext_type=sa.text()), nullable=False, server_default=sa.text("'[]'::jsonb")),
    )


def downgrade() -> None:
    op.drop_column("swx_oidc_clients", "post_logout_redirect_uris")