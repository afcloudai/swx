"""
Alembic Migration: v2.31.1 Relax swx_users.email to nullable (SWX-IDM-001)
==========================================================================

Person-first identity: email is the OPTIONAL channel (the phone-verified
identity is the norm). Unique/index stays — Postgres unique indexes allow
multiple NULLs, so accounts without email are legal.

This is a standalone template revision. Copy this file into your project's
``migrations/versions/``, set ``down_revision`` to your current head, and run
``alembic upgrade head``.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "v2_31_1_relax_user_email_nullable"
down_revision: str | None = None
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.alter_column("swx_users", "email", existing_type=sa.String(255), nullable=True)


def downgrade() -> None:
    op.execute("UPDATE swx_users SET email = CONCAT('deleted-', id::text, '@invalid.local') WHERE email IS NULL")
    op.alter_column("swx_users", "email", existing_type=sa.String(255), nullable=False)
