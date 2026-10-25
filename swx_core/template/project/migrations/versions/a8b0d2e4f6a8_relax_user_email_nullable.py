"""relax swx_users.email to nullable (SWX-IDM-001)

Revision ID: a8b0d2e4f6a8
Revises: f7a9c1d3e5b7
Create Date: 2026-10-25 00:00:00.000000

Email becomes the optional verification channel (phone-first identity norm);
unique index retained (Postgres allows multiple NULLs).
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "a8b0d2e4f6a8"
down_revision: str | None = "f7a9c1d3e5b7"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.alter_column("swx_users", "email", existing_type=sa.String(255), nullable=True)


def downgrade() -> None:
    op.execute("UPDATE swx_users SET email = CONCAT('deleted-', id::text, '@invalid.local') WHERE email IS NULL")
    op.alter_column("swx_users", "email", existing_type=sa.String(255), nullable=False)
