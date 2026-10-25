# pyright: reportMissingImports=false, reportAny=false, reportExplicitAny=false, reportUnknownMemberType=false, reportUnknownArgumentType=false, reportUnusedCallResult=false

"""
OIDC client admin service (SWX-IDM-001, D-2)
--------------------------------------------
CRUD for registered OIDC clients plus consent/revocation operations, guarded
at the route layer by ``AdminUserDep`` + the ``idp:clients:*`` permission set.

Fail-closed rules enforced here:
- redirect URIs: absolute, fragment-free, wildcard-free (exact-match checked
  again at /authorize on the stored list)
- grant types/scopes restricted to the v1 registry
- public clients (no secret) may not use ``client_credentials``
- client secrets are bcrypt-hashed on write and never returned
"""

import re
import uuid
from typing import Any
from urllib.parse import urlsplit

from fastapi import Request
from sqlalchemy.ext.asyncio import AsyncSession

from swx_core.auth.oidc_provider import repositories as oidc_repo
from swx_core.auth.oidc_provider.models import OIDCClient, OIDCClientCreate, OIDCClientPublic, OIDCClientUpdate
from swx_core.security.password_security import get_password_hash
from swx_core.services.audit_logger import ActorType, AuditAction, AuditLogger, AuditOutcome

SUPPORTED_GRANT_TYPES = frozenset({"authorization_code", "refresh_token", "client_credentials"})
SUPPORTED_SCOPES = frozenset({"openid", "profile", "phone"})

_CLIENT_ID_RE = re.compile(r"^[A-Za-z0-9_-]{6,64}$")
_FORBIDDEN_REDIRECT_CHARS = frozenset("*? \t\r\n")


class OIDCValidationError(ValueError):
    """Payload rejected by OIDC client validation (maps to HTTP 400)."""


def _to_public(client: OIDCClient) -> OIDCClientPublic:
    data: dict[str, Any] = client.model_dump()
    data["has_client_secret"] = client.client_secret_hash is not None
    data.pop("client_secret_hash", None)
    return OIDCClientPublic.model_validate(data)


def _validate_redirect_uris(redirect_uris: list[str]) -> None:
    if not redirect_uris:
        raise OIDCValidationError("At least one redirect URI is required")
    for uri in redirect_uris:
        parts = urlsplit(uri)
        if not parts.scheme or not parts.netloc:
            raise OIDCValidationError(f"Redirect URI must be absolute: {uri!r}")
        if parts.fragment:
            raise OIDCValidationError(f"Redirect URI must not contain a fragment: {uri!r}")
        if any(ch in _FORBIDDEN_REDIRECT_CHARS for ch in uri):
            raise OIDCValidationError(f"Redirect URI contains forbidden characters: {uri!r}")


def _validate_collection_field(values: list[str], allowed: frozenset[str], field: str) -> None:
    unknown = set(values) - allowed
    if unknown:
        raise OIDCValidationError(f"Unsupported {field}: {sorted(unknown)}")


def _resolve_ttl(value: int | None, name: str) -> int | None:
    if value is None:
        return None
    if value <= 0:
        raise OIDCValidationError(f"{name} must be positive")
    return value


async def _hash_client_secret(plain: str) -> str | None:
    if not plain:
        raise OIDCValidationError("client_secret must be a non-empty string")
    return await get_password_hash(plain)


async def _audit(
    session: AsyncSession,
    action: str | AuditAction,
    *,
    outcome: AuditOutcome,
    context: dict[str, Any],
    actor_id: str | None,
    resource_id: str | None,
    request: Request | None,
) -> None:
    await AuditLogger(session).log_event(
        action=action,
        actor_type=ActorType.ADMIN,
        actor_id=actor_id,
        resource_type="oidc_client",
        resource_id=resource_id,
        outcome=outcome,
        context=context,
        request=request,
    )


async def create_client(
    session: AsyncSession,
    body: OIDCClientCreate,
    *,
    actor_id: str | None = None,
    request: Request | None = None,
) -> OIDCClientPublic:
    _validate_redirect_uris(body.redirect_uris)
    grant_types = body.grant_types if body.grant_types is not None else ["authorization_code", "refresh_token"]
    scopes = body.scopes if body.scopes is not None else ["openid", "profile", "phone"]
    _validate_collection_field(grant_types, SUPPORTED_GRANT_TYPES, "grant_types")
    _validate_collection_field(scopes, SUPPORTED_SCOPES, "scopes")
    if body.client_id is not None and not _CLIENT_ID_RE.fullmatch(body.client_id):
        raise OIDCValidationError("client_id must match ^[A-Za-z0-9_-]{6,64}$")

    client_id = body.client_id or uuid.uuid4().hex
    secret_hash = await _hash_client_secret(body.client_secret) if body.client_secret is not None else None
    if secret_hash is None and "client_credentials" in grant_types:
        raise OIDCValidationError("client_credentials requires a confidential client (client_secret)")

    data: dict[str, Any] = {
        "name": body.name,
        "client_id": client_id,
        "client_secret_hash": secret_hash,
        "logo_url": body.logo_url,
        "redirect_uris": body.redirect_uris,
        "grant_types": grant_types,
        "scopes": scopes,
        "is_first_party": body.is_first_party,
        "is_trusted": body.is_trusted,
        "enabled": body.enabled,
        "access_token_ttl_seconds": _resolve_ttl(body.access_token_ttl_seconds, "access_token_ttl_seconds") or 3600,
        "id_token_ttl_seconds": _resolve_ttl(body.id_token_ttl_seconds, "id_token_ttl_seconds") or 3600,
        "refresh_token_ttl_seconds": _resolve_ttl(body.refresh_token_ttl_seconds, "refresh_token_ttl_seconds") or 1209600,
    }
    client = await oidc_repo.create_client(session, data)
    await _audit(
        session,
        AuditAction.AUTH_OAUTH_CLIENT_CREATED,
        outcome=AuditOutcome.SUCCESS,
        context={"client_name": client.name, "is_first_party": client.is_first_party, "grant_types": client.grant_types},
        actor_id=actor_id,
        resource_id=client.client_id,
        request=request,
    )
    return _to_public(client)


async def get_client(session: AsyncSession, client_row_id: uuid.UUID) -> OIDCClientPublic:
    client = await oidc_repo.get_client_by_id(session, client_row_id)
    if client is None:
        raise ValueError("OIDC client not found")
    return _to_public(client)


async def list_clients(
    session: AsyncSession, *, skip: int = 0, limit: int = 100, enabled: bool | None = None
) -> list[OIDCClientPublic]:
    clients = await oidc_repo.list_clients(session, enabled=enabled, skip=skip, limit=limit)
    return [_to_public(client) for client in clients]


async def update_client(
    session: AsyncSession,
    client_row_id: uuid.UUID,
    body: OIDCClientUpdate,
    *,
    actor_id: str | None = None,
    request: Request | None = None,
) -> OIDCClientPublic:
    client = await oidc_repo.get_client_by_id(session, client_row_id)
    if client is None:
        raise ValueError("OIDC client not found")

    updates: dict[str, Any] = body.model_dump(exclude_unset=True, exclude={"client_secret"})
    if body.redirect_uris is not None:
        _validate_redirect_uris(body.redirect_uris)
    if body.grant_types is not None:
        _validate_collection_field(body.grant_types, SUPPORTED_GRANT_TYPES, "grant_types")
    if body.scopes is not None:
        _validate_collection_field(body.scopes, SUPPORTED_SCOPES, "scopes")
    for name in ("access_token_ttl_seconds", "id_token_ttl_seconds", "refresh_token_ttl_seconds"):
        _resolve_ttl(getattr(body, name), name)

    grant_types = updates.get("grant_types", client.grant_types)
    secret_hash = client.client_secret_hash
    if body.client_secret is not None:
        secret_hash = await _hash_client_secret(body.client_secret)
    if body.client_secret is None and secret_hash is None and "client_credentials" in grant_types:
        raise OIDCValidationError("client_credentials requires a confidential client (client_secret)")

    updates["client_secret_hash"] = secret_hash
    updated = await oidc_repo.update_client(session, client, updates)
    await _audit(
        session,
        AuditAction.AUTH_OAUTH_CLIENT_UPDATED,
        outcome=AuditOutcome.SUCCESS,
        context={"client_name": updated.name, "fields": sorted({*updates} - {"client_secret_hash"})},
        actor_id=actor_id,
        resource_id=updated.client_id,
        request=request,
    )
    return _to_public(updated)


async def delete_client(
    session: AsyncSession,
    client_row_id: uuid.UUID,
    *,
    actor_id: str | None = None,
    request: Request | None = None,
) -> dict[str, int]:
    client = await oidc_repo.get_client_by_id(session, client_row_id)
    if client is None:
        raise ValueError("OIDC client not found")
    client_id = client.client_id
    counts = await oidc_repo.delete_client_cascade(session, client)
    await _audit(
        session,
        AuditAction.AUTH_OAUTH_CLIENT_DELETED,
        outcome=AuditOutcome.SUCCESS,
        context={"client_id": client_id, **counts},
        actor_id=actor_id,
        resource_id=client_id,
        request=request,
    )
    return counts