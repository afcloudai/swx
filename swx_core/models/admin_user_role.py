# pyright: reportUnannotatedClassAttribute=false

"""
Admin User-Role Assignment
--------------------------
Many-to-many binding between admin-domain identities (``swx_admin_user``) and
RBAC roles. Without this binding, roles and permissions can only attach to
regular users (``swx_user_role``), leaving admin-surface RBAC unenforceable;
this table closes that gap and enables strict permission checks such as
``idp:clients:*`` on ``/admin/*`` routes.
"""

import uuid
from datetime import datetime
from typing import Any, cast

from sqlalchemy import Column, DateTime, ForeignKey, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlmodel import Field, SQLModel

from swx_core.models.base import Base
from swx_core.utils.time import utc_now


class AdminUserRoleBase(Base):
    pass


class AdminUserRole(AdminUserRoleBase, table=True):
    __tablename__ = cast(Any, "swx_admin_user_roles")
    __table_args__ = cast(
        Any,
        (
            UniqueConstraint("admin_user_id", "role_id", name="uq_admin_user_role"),
            {"extend_existing": True},
        ),
    )

    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    admin_user_id: uuid.UUID = Field(
        sa_column=Column(
            "admin_user_id",
            PG_UUID(as_uuid=True),
            ForeignKey("swx_admin_user.id", ondelete="CASCADE"),
            index=True,
            nullable=False,
        ),
    )
    role_id: uuid.UUID = Field(
        sa_column=Column(
            "role_id",
            PG_UUID(as_uuid=True),
            ForeignKey("swx_role.id", ondelete="CASCADE"),
            index=True,
            nullable=False,
        ),
    )
    created_at: datetime = Field(
        default_factory=utc_now,
        sa_column=Column(DateTime(timezone=True), nullable=False, server_default=func.now()),
    )


class AdminUserRoleCreate(SQLModel):
    admin_user_id: uuid.UUID
    role_id: uuid.UUID


class AdminUserRolePublic(SQLModel):
    id: uuid.UUID
    admin_user_id: uuid.UUID
    role_id: uuid.UUID
    created_at: datetime

    model_config = {"from_attributes": True}