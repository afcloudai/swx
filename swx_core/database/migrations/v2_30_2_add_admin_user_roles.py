"""
Alembic Migration: v2.30.2 Add admin user-role bindings (SWX-IDM-001)
=====================================================================

Creates ``swx_admin_user_roles`` — the many-to-many binding between
admin-domain identities (``swx_admin_user``) and RBAC roles — enabling strict
admin-surface permission enforcement (e.g. ``idp:clients:*``).

This is a standalone template revision. Copy this file into your project's
``migrations/versions/``, set ``down_revision`` to your current head, and run
``alembic upgrade head``.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "v2_30_2_admin_user_roles"
down_revision: str | None = None
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "swx_admin_user_roles",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "admin_user_id",
            sa.Uuid(),
            sa.ForeignKey("swx_admin_user.id", ondelete="CASCADE"),
            nullable=False,
            index=True,
        ),
        sa.Column(
            "role_id",
            sa.Uuid(),
            sa.ForeignKey("swx_role.id", ondelete="CASCADE"),
            nullable=False,
            index=True,
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("admin_user_id", "role_id", name="uq_admin_user_role"),
    )


def downgrade() -> None:
    op.drop_table("swx_admin_user_roles")