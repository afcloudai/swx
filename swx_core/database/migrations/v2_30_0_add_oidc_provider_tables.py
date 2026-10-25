"""
Alembic Migration: v2.30.0 Add OIDC identity-provider tables (SWX-IDM-001)
==========================================================================

Creates the OIDC provider tables:

- ``swx_oidc_clients``        — registered clients (secret hashed; exact redirect list)
- ``swx_oidc_grant_codes``    — single-use authorization codes (hash-stored, short TTL)
- ``swx_oidc_consents``       — user × client scope consents
- ``swx_oidc_refresh_tokens`` — rotation-family refresh tokens (hash-stored)
- ``swx_oidc_signing_keys``   — RS256/EdDSA signing keys with kid + retirement

This is a standalone template revision. Copy this file into your project's
``migrations/versions/``, set ``down_revision`` to your current head, and run
``alembic upgrade head``.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "v2_30_0_oidc_provider_tables"
down_revision: str | None = None
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "swx_oidc_clients",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("client_id", sa.String(64), nullable=False, unique=True, index=True),
        sa.Column("client_secret_hash", sa.String(255), nullable=True),
        sa.Column("logo_url", sa.String(1000), nullable=True),
        sa.Column("redirect_uris", postgresql.JSONB(astext_type=sa.text()), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("grant_types", postgresql.JSONB(astext_type=sa.text()), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("scopes", postgresql.JSONB(astext_type=sa.text()), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("is_first_party", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("is_trusted", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("access_token_ttl_seconds", sa.Integer(), nullable=False),
        sa.Column("id_token_ttl_seconds", sa.Integer(), nullable=False),
        sa.Column("refresh_token_ttl_seconds", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )

    op.create_table(
        "swx_oidc_grant_codes",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("code_hash", sa.String(255), nullable=False, index=True),
        sa.Column("client_id", sa.String(64), nullable=False, index=True),
        sa.Column("user_id", sa.Uuid(), sa.ForeignKey("swx_users.id"), nullable=False, index=True),
        sa.Column("redirect_uri", sa.String(1000), nullable=False),
        sa.Column("scope", sa.String(500), nullable=False),
        sa.Column("code_challenge", sa.String(128), nullable=True),
        sa.Column("code_challenge_method", sa.String(10), nullable=True),
        sa.Column("nonce", sa.String(255), nullable=True),
        sa.Column("auth_time", sa.DateTime(timezone=True), nullable=True),
        sa.Column("acr", sa.String(100), nullable=True),
        sa.Column("amr", postgresql.JSONB(astext_type=sa.text()), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False, index=True),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_oidc_grant_codes_client_user", "swx_oidc_grant_codes", ["client_id", "user_id"])

    op.create_table(
        "swx_oidc_consents",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("user_id", sa.Uuid(), sa.ForeignKey("swx_users.id"), nullable=False, index=True),
        sa.Column("client_id", sa.String(64), nullable=False, index=True),
        sa.Column("scope", sa.String(500), nullable=False),
        sa.Column("granted_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("user_id", "client_id", name="uq_oidc_consent_user_client"),
    )

    op.create_table(
        "swx_oidc_refresh_tokens",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("family_id", sa.Uuid(), nullable=False, index=True),
        sa.Column("token_hash", sa.String(255), nullable=False, unique=True, index=True),
        sa.Column("client_id", sa.String(64), nullable=False, index=True),
        sa.Column("user_id", sa.Uuid(), sa.ForeignKey("swx_users.id"), nullable=False, index=True),
        sa.Column("scope", sa.String(500), nullable=False),
        sa.Column("status", sa.String(20), nullable=False, index=True, server_default=sa.text("'active'")),
        sa.Column("auth_time", sa.DateTime(timezone=True), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False, index=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_oidc_refresh_tokens_family_status", "swx_oidc_refresh_tokens", ["family_id", "status"])

    op.create_table(
        "swx_oidc_signing_keys",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("kid", sa.String(100), nullable=False, unique=True, index=True),
        sa.Column("algorithm", sa.String(20), nullable=False),
        sa.Column("private_key_encrypted", sa.String(5000), nullable=False),
        sa.Column("public_jwk", postgresql.JSONB(astext_type=sa.text()), nullable=False),
        sa.Column("status", sa.String(20), nullable=False, index=True, server_default=sa.text("'active'")),
        sa.Column("retires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index(
        "uq_oidc_signing_keys_single_active",
        "swx_oidc_signing_keys",
        ["status"],
        unique=True,
        postgresql_where=sa.text("status = 'active'"),
    )


def downgrade() -> None:
    op.drop_index("uq_oidc_signing_keys_single_active", table_name="swx_oidc_signing_keys")
    op.drop_table("swx_oidc_signing_keys")
    op.drop_index("ix_oidc_refresh_tokens_family_status", table_name="swx_oidc_refresh_tokens")
    op.drop_table("swx_oidc_refresh_tokens")
    op.drop_table("swx_oidc_consents")
    op.drop_index("ix_oidc_grant_codes_client_user", table_name="swx_oidc_grant_codes")
    op.drop_table("swx_oidc_grant_codes")
    op.drop_table("swx_oidc_clients")