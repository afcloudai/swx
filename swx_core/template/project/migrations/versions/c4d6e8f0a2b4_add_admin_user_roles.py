"""add admin user-role bindings (SWX-IDM-001)

Revision ID: c4d6e8f0a2b4
Revises: b3e5c7d9f1a2
Create Date: 2026-10-24 00:00:00.000000

Creates swx_admin_user_roles — binds admin-domain identities to RBAC roles so
admin-surface permissions (idp:clients:*) become strictly enforceable.
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "c4d6e8f0a2b4"
down_revision: str | None = "b3e5c7d9f1a2"
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