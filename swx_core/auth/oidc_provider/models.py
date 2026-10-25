# pyright: reportUnannotatedClassAttribute=false

"""
OIDC provider models
--------------------
Tables backing the swx-core OIDC identity provider (SWX-IDM-001):

- ``swx_oidc_clients``        — registered OAuth/OIDC clients (first-party in v1)
- ``swx_oidc_grant_codes``    — single-use short-lived authorization codes
- ``swx_oidc_consents``       — user × client scope consents (recorded even for trusted clients)
- ``swx_oidc_refresh_tokens`` — OIDC refresh tokens with rotation families (hash-stored)
- ``swx_oidc_signing_keys``   — asymmetric signing keys (RS256/EdDSA) with kid rotation

Client secrets and signing private keys are stored encrypted at rest via
``swx_core.security.encryption``; public schemas never expose them.
"""

import uuid
from datetime import datetime
from typing import Any, cast

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Index, String, UniqueConstraint, func, text
from sqlalchemy.dialects.postgresql import JSONB, UUID as PG_UUID
from sqlmodel import Field, SQLModel

from swx_core.models.base import Base
from swx_core.utils.time import utc_now

# Token-refresh lifecycle states (rotate/revoke only; a fresh token starts active)
REFRESH_STATUS_ACTIVE = "active"
REFRESH_STATUS_ROTATED = "rotated"
REFRESH_STATUS_REVOKED = "revoked"

# Signing-key lifecycle states
KEY_STATUS_ACTIVE = "active"        # signs new tokens
KEY_STATUS_VERIFY_ONLY = "verify_only"  # validates old tokens until retires_at


def _default_grant_types() -> list[str]:
    return ["authorization_code", "refresh_token"]


def _default_scopes() -> list[str]:
    return ["openid", "profile", "phone"]


class OIDCClientBase(Base):
    name: str = Field(max_length=200)
    client_id: str = Field(max_length=64, sa_column=Column(String(64), nullable=False, unique=True, index=True))
    client_secret_hash: str | None = Field(default=None, max_length=255)  # bcrypt; None ⇒ public client
    logo_url: str | None = Field(default=None, max_length=1000)
    redirect_uris: list[str] = Field(sa_column=Column(JSONB, nullable=False, server_default=text("'[]'::jsonb")))
    post_logout_redirect_uris: list[str] = Field(default_factory=list, sa_column=Column(JSONB, nullable=False, server_default=text("'[]'::jsonb")))
    grant_types: list[str] = Field(default_factory=_default_grant_types, sa_column=Column(JSONB, nullable=False, server_default=text("'[]'::jsonb")))
    scopes: list[str] = Field(default_factory=_default_scopes, sa_column=Column(JSONB, nullable=False, server_default=text("'[]'::jsonb")))
    is_first_party: bool = Field(default=True, sa_column=Column(Boolean, nullable=False, server_default=text("true")))
    is_trusted: bool = Field(default=False, sa_column=Column(Boolean, nullable=False, server_default=text("false")))
    enabled: bool = Field(default=True, sa_column=Column(Boolean, nullable=False, server_default=text("true")))
    access_token_ttl_seconds: int = Field(default=3600)
    id_token_ttl_seconds: int = Field(default=3600)
    refresh_token_ttl_seconds: int = Field(default=1209600)


class OIDCClient(OIDCClientBase, table=True):
    __tablename__ = cast(Any, "swx_oidc_clients")
    __table_args__ = cast(Any, {"extend_existing": True})

    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    created_at: datetime = Field(default_factory=utc_now, sa_column=Column(DateTime(timezone=True), nullable=False, server_default=func.now()))
    updated_at: datetime = Field(default_factory=utc_now, sa_column=Column(DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now()))


class OIDCClientCreate(SQLModel):
    """Creation schema — carries the PLAIN client secret (hashed on write, never returned)."""

    name: str = Field(max_length=200)
    client_id: str | None = Field(default=None, max_length=64)
    client_secret: str | None = Field(default=None, max_length=500)
    logo_url: str | None = Field(default=None, max_length=1000)
    redirect_uris: list[str] = Field(min_length=1)
    post_logout_redirect_uris: list[str] | None = None
    grant_types: list[str] | None = None
    scopes: list[str] | None = None
    is_first_party: bool = True
    is_trusted: bool = False
    enabled: bool = True
    access_token_ttl_seconds: int | None = None
    id_token_ttl_seconds: int | None = None
    refresh_token_ttl_seconds: int | None = None


class OIDCClientUpdate(SQLModel):
    """Update schema — ``client_secret`` set ⇒ rotate secret; None ⇒ unchanged."""

    name: str | None = Field(default=None, max_length=200)
    client_secret: str | None = Field(default=None, max_length=500)
    logo_url: str | None = Field(default=None, max_length=1000)
    redirect_uris: list[str] | None = None
    post_logout_redirect_uris: list[str] | None = None
    grant_types: list[str] | None = None
    scopes: list[str] | None = None
    is_first_party: bool | None = None
    is_trusted: bool | None = None
    enabled: bool | None = None
    access_token_ttl_seconds: int | None = None
    id_token_ttl_seconds: int | None = None
    refresh_token_ttl_seconds: int | None = None


class OIDCClientPublic(SQLModel):
    """Public schema — deliberately excludes the secret hash (fail-closed by type, not by masking)."""

    id: uuid.UUID
    client_id: str
    name: str
    logo_url: str | None
    redirect_uris: list[str]
    grant_types: list[str]
    scopes: list[str]
    is_first_party: bool
    is_trusted: bool
    enabled: bool
    access_token_ttl_seconds: int
    id_token_ttl_seconds: int
    refresh_token_ttl_seconds: int
    has_client_secret: bool
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class OIDCGrantCodeBase(Base):
    code_hash: str = Field(max_length=255, sa_column=Column(String(255), nullable=False, index=True))
    client_id: str = Field(max_length=64, sa_column=Column(String(64), nullable=False, index=True))
    user_id: uuid.UUID = Field(sa_column=Column(PG_UUID(as_uuid=True), ForeignKey("swx_users.id"), nullable=False, index=True))
    redirect_uri: str = Field(max_length=1000, sa_column=Column(String(1000), nullable=False))
    scope: str = Field(max_length=500, sa_column=Column(String(500), nullable=False))
    code_challenge: str | None = Field(default=None, max_length=128, sa_column=Column(String(128), nullable=True))
    code_challenge_method: str | None = Field(default=None, max_length=10, sa_column=Column(String(10), nullable=True))
    nonce: str | None = Field(default=None, max_length=255, sa_column=Column(String(255), nullable=True))
    auth_time: datetime | None = Field(default=None, sa_column=Column(DateTime(timezone=True), nullable=True))
    acr: str | None = Field(default=None, max_length=100, sa_column=Column(String(100), nullable=True))
    amr: list[str] | None = Field(default=None, sa_column=Column("amr", JSONB, nullable=True))
    expires_at: datetime = Field(sa_column=Column(DateTime(timezone=True), nullable=False, index=True))
    consumed_at: datetime | None = Field(default=None, sa_column=Column(DateTime(timezone=True), nullable=True))


class OIDCGrantCode(OIDCGrantCodeBase, table=True):
    __tablename__ = cast(Any, "swx_oidc_grant_codes")
    __table_args__ = cast(
        Any,
        (
            Index("ix_oidc_grant_codes_client_user", "client_id", "user_id"),
            {"extend_existing": True},
        ),
    )

    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    created_at: datetime = Field(default_factory=utc_now, sa_column=Column(DateTime(timezone=True), nullable=False, server_default=func.now()))


class OIDCGrantCodePublic(SQLModel):
    id: uuid.UUID
    client_id: str
    user_id: uuid.UUID
    redirect_uri: str
    scope: str
    expires_at: datetime
    consumed_at: datetime | None
    created_at: datetime

    model_config = {"from_attributes": True}


class OIDCConsentBase(Base):
    user_id: uuid.UUID = Field(sa_column=Column(PG_UUID(as_uuid=True), ForeignKey("swx_users.id"), nullable=False, index=True))
    client_id: str = Field(max_length=64, sa_column=Column(String(64), nullable=False, index=True))
    scope: str = Field(max_length=500, sa_column=Column(String(500), nullable=False))
    granted_at: datetime = Field(default_factory=utc_now, sa_column=Column(DateTime(timezone=True), nullable=False, server_default=func.now()))
    revoked_at: datetime | None = Field(default=None, sa_column=Column(DateTime(timezone=True), nullable=True))


class OIDCConsent(OIDCConsentBase, table=True):
    __tablename__ = cast(Any, "swx_oidc_consents")
    __table_args__ = cast(
        Any,
        (
            UniqueConstraint("user_id", "client_id", name="uq_oidc_consent_user_client"),
            {"extend_existing": True},
        ),
    )

    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)


class OIDCConsentCreate(SQLModel):
    user_id: uuid.UUID
    client_id: str = Field(max_length=64)
    scope: str = Field(max_length=500)


class OIDCConsentPublic(SQLModel):
    id: uuid.UUID
    user_id: uuid.UUID
    client_id: str
    scope: str
    granted_at: datetime
    revoked_at: datetime | None

    model_config = {"from_attributes": True}


class OIDCRefreshTokenBase(Base):
    family_id: uuid.UUID = Field(sa_column=Column(PG_UUID(as_uuid=True), nullable=False, index=True))
    token_hash: str = Field(max_length=255, sa_column=Column(String(255), nullable=False, unique=True, index=True))
    client_id: str = Field(max_length=64, sa_column=Column(String(64), nullable=False, index=True))
    user_id: uuid.UUID = Field(sa_column=Column(PG_UUID(as_uuid=True), ForeignKey("swx_users.id"), nullable=False, index=True))
    scope: str = Field(max_length=500, sa_column=Column(String(500), nullable=False))
    status: str = Field(default=REFRESH_STATUS_ACTIVE, max_length=20, sa_column=Column(String(20), nullable=False, index=True, server_default=text("'active'")))
    auth_time: datetime | None = Field(default=None, sa_column=Column(DateTime(timezone=True), nullable=True))
    expires_at: datetime = Field(sa_column=Column(DateTime(timezone=True), nullable=False, index=True))


class OIDCRefreshToken(OIDCRefreshTokenBase, table=True):
    __tablename__ = cast(Any, "swx_oidc_refresh_tokens")
    __table_args__ = cast(
        Any,
        (
            Index("ix_oidc_refresh_tokens_family_status", "family_id", "status"),
            {"extend_existing": True},
        ),
    )

    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    created_at: datetime = Field(default_factory=utc_now, sa_column=Column(DateTime(timezone=True), nullable=False, server_default=func.now()))


class OIDCRefreshTokenPublic(SQLModel):
    id: uuid.UUID
    family_id: uuid.UUID
    client_id: str
    user_id: uuid.UUID
    scope: str
    status: str
    expires_at: datetime
    created_at: datetime

    model_config = {"from_attributes": True}


class OIDCSigningKeyBase(Base):
    kid: str = Field(max_length=100, sa_column=Column(String(100), nullable=False, unique=True, index=True))
    algorithm: str = Field(max_length=20, sa_column=Column(String(20), nullable=False))
    private_key_encrypted: str = Field(max_length=5000, sa_column=Column(String(5000), nullable=False))
    public_jwk: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSONB, nullable=False))
    status: str = Field(default=KEY_STATUS_ACTIVE, max_length=20, sa_column=Column(String(20), nullable=False, index=True, server_default=text("'active'")))
    retires_at: datetime | None = Field(default=None, sa_column=Column(DateTime(timezone=True), nullable=True))


class OIDCSigningKey(OIDCSigningKeyBase, table=True):
    __tablename__ = cast(Any, "swx_oidc_signing_keys")
    __table_args__ = cast(Any, {"extend_existing": True})

    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    created_at: datetime = Field(default_factory=utc_now, sa_column=Column(DateTime(timezone=True), nullable=False, server_default=func.now()))


class OIDCSigningKeyCreate(SQLModel):
    kid: str = Field(max_length=100)
    algorithm: str = Field(max_length=20)
    private_key_encrypted: str = Field(max_length=5000)
    public_jwk: dict[str, Any]
    status: str = Field(default=KEY_STATUS_ACTIVE, max_length=20)
    retires_at: datetime | None = None


class OIDCSigningKeyPublic(SQLModel):
    """Public schema — excludes the encrypted private key entirely."""

    id: uuid.UUID
    kid: str
    algorithm: str
    status: str
    retires_at: datetime | None
    created_at: datetime

    model_config = {"from_attributes": True}