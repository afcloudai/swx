# pyright: reportAny=false, reportExplicitAny=false, reportUnknownMemberType=false, reportUnknownArgumentType=false, reportUnusedCallResult=false, reportMissingImports=false

"""
OIDC provider repositories
--------------------------
Session-explicit data access for the OIDC provider module, mirroring the
framework house style (see ``repositories/sso_repository.py``).

Rotation-safety note: ``rotate_refresh_tokens`` and ``consume_grant_code`` are
atomic single-row state transitions — replay and concurrent-exchange races
resolve to a refused (``None``/``False``) result, never to double issuance.
"""

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import delete, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from swx_core.auth.oidc_provider.models import (
    KEY_STATUS_ACTIVE,
    KEY_STATUS_VERIFY_ONLY,
    OIDCClient,
    OIDCConsent,
    OIDCGrantCode,
    OIDCRefreshToken,
    OIDCSigningKey,
    REFRESH_STATUS_ACTIVE,
    REFRESH_STATUS_REVOKED,
    REFRESH_STATUS_ROTATED,
)
from swx_core.utils.time import utc_now


def _apply_updates(instance: Any, updates: dict[str, Any]) -> Any:
    for field_name, value in updates.items():
        setattr(instance, field_name, value)
    return instance


# ---------------------------------------------------------------------------
# Clients
# ---------------------------------------------------------------------------


async def create_client(session: AsyncSession, data: dict[str, Any]) -> OIDCClient:
    client = OIDCClient(**data)
    session.add(client)
    await session.commit()
    await session.refresh(client)
    return client


async def get_client_by_id(session: AsyncSession, client_row_id: uuid.UUID) -> OIDCClient | None:
    return await session.get(OIDCClient, client_row_id)


async def get_client_by_public_id(session: AsyncSession, client_id: str) -> OIDCClient | None:
    stmt = select(OIDCClient).where(OIDCClient.client_id == client_id)
    return (await session.execute(stmt)).scalar_one_or_none()


async def list_clients(
    session: AsyncSession, *, enabled: bool | None = None, skip: int = 0, limit: int = 100
) -> list[OIDCClient]:
    stmt = select(OIDCClient)
    if enabled is not None:
        stmt = stmt.where(OIDCClient.enabled == enabled)
    stmt = stmt.order_by(OIDCClient.name.asc()).offset(skip).limit(limit)
    return list((await session.execute(stmt)).scalars().all())


async def update_client(session: AsyncSession, client: OIDCClient, data: dict[str, Any]) -> OIDCClient:
    _apply_updates(client, {**data, "updated_at": utc_now()})
    session.add(client)
    await session.commit()
    await session.refresh(client)
    return client


async def delete_client_cascade(
    session: AsyncSession, client: OIDCClient
) -> dict[str, int]:
    """Delete a client and every dependent state in one transaction.

    Grant codes and consents are deleted; refresh tokens are revoked (not
    deleted) so an in-flight reuse attempt still resolves to refusal.
    Returns per-table row counts for the audit context.
    """
    counts: dict[str, int] = {}

    codes_result = await session.execute(
        delete(OIDCGrantCode).where(OIDCGrantCode.client_id == client.client_id)
    )
    counts["grant_codes"] = codes_result.rowcount or 0

    consent_result = await session.execute(
        delete(OIDCConsent).where(OIDCConsent.client_id == client.client_id)
    )
    counts["consents"] = consent_result.rowcount or 0

    refresh_result = await session.execute(
        update(OIDCRefreshToken)
        .where(OIDCRefreshToken.client_id == client.client_id)
        .where(OIDCRefreshToken.status != REFRESH_STATUS_REVOKED)
        .values(status=REFRESH_STATUS_REVOKED)
    )
    counts["refresh_tokens_revoked"] = refresh_result.rowcount or 0

    await session.delete(client)
    await session.commit()
    return counts


# ---------------------------------------------------------------------------
# Grant codes (single-use authorization codes)
# ---------------------------------------------------------------------------


async def create_grant_code(session: AsyncSession, data: dict[str, Any]) -> OIDCGrantCode:
    code = OIDCGrantCode(**data)
    session.add(code)
    await session.commit()
    await session.refresh(code)
    return code


async def get_grant_code_by_hash(session: AsyncSession, code_hash: str) -> OIDCGrantCode | None:
    stmt = select(OIDCGrantCode).where(OIDCGrantCode.code_hash == code_hash)
    return (await session.execute(stmt)).scalar_one_or_none()


async def consume_grant_code(session: AsyncSession, code_id: uuid.UUID) -> bool:
    """Atomically mark a grant code consumed; ``False`` means it was already used."""
    result = await session.execute(
        update(OIDCGrantCode)
        .where(OIDCGrantCode.id == code_id)
        .where(OIDCGrantCode.consumed_at.is_(None))
        .values(consumed_at=utc_now())
    )
    await session.commit()
    return bool(result.rowcount)


# ---------------------------------------------------------------------------
# Consents
# ---------------------------------------------------------------------------


async def get_consent(session: AsyncSession, user_id: uuid.UUID, client_id: str) -> OIDCConsent | None:
    stmt = select(OIDCConsent).where(
        OIDCConsent.user_id == user_id,
        OIDCConsent.client_id == client_id,
    )
    return (await session.execute(stmt)).scalar_one_or_none()


async def upsert_consent(
    session: AsyncSession, *, user_id: uuid.UUID, client_id: str, scope: str
) -> OIDCConsent:
    """Grant (or widen) a consent; a revoked row is re-activated."""
    consent = await get_consent(session, user_id, client_id)
    if consent is None:
        consent = OIDCConsent(user_id=user_id, client_id=client_id, scope=scope, granted_at=utc_now())
        session.add(consent)
    else:
        _apply_updates(consent, {"scope": scope, "granted_at": utc_now(), "revoked_at": None})
        session.add(consent)
    await session.commit()
    await session.refresh(consent)
    return consent


async def revoke_consent(session: AsyncSession, user_id: uuid.UUID, client_id: str) -> OIDCConsent | None:
    consent = await get_consent(session, user_id, client_id)
    if consent is None or consent.revoked_at is not None:
        return consent if consent else None
    _apply_updates(consent, {"revoked_at": utc_now()})
    session.add(consent)
    await session.commit()
    await session.refresh(consent)
    return consent


async def revoke_consents_for_client(session: AsyncSession, client_id: str) -> int:
    result = await session.execute(
        update(OIDCConsent)
        .where(OIDCConsent.client_id == client_id)
        .where(OIDCConsent.revoked_at.is_(None))
        .values(revoked_at=utc_now())
    )
    await session.commit()
    return result.rowcount or 0


# ---------------------------------------------------------------------------
# Refresh tokens (rotation families)
# ---------------------------------------------------------------------------


async def create_refresh_token(session: AsyncSession, data: dict[str, Any]) -> OIDCRefreshToken:
    token = OIDCRefreshToken(**data)
    session.add(token)
    await session.commit()
    await session.refresh(token)
    return token


async def get_refresh_token_by_hash(session: AsyncSession, token_hash: str) -> OIDCRefreshToken | None:
    stmt = select(OIDCRefreshToken).where(OIDCRefreshToken.token_hash == token_hash)
    return (await session.execute(stmt)).scalar_one_or_none()


async def rotate_refresh_tokens(
    session: AsyncSession, *, old_id: uuid.UUID, new_data: dict[str, Any]
) -> OIDCRefreshToken | None:
    """Rotate atomically: old ``active`` → ``rotated``; new row inserted in the same transaction.

    Returns ``None`` when the old token was not active (already rotated/revoked)
    — the caller treats that as refresh-token reuse.
    """
    result = await session.execute(
        update(OIDCRefreshToken)
        .where(OIDCRefreshToken.id == old_id)
        .where(OIDCRefreshToken.status == REFRESH_STATUS_ACTIVE)
        .values(status=REFRESH_STATUS_ROTATED)
    )
    if not result.rowcount:
        await session.commit()
        return None
    token = OIDCRefreshToken(**new_data, status=REFRESH_STATUS_ACTIVE)
    session.add(token)
    await session.commit()
    await session.refresh(token)
    return token


async def revoke_family(session: AsyncSession, family_id: uuid.UUID) -> int:
    """Revoke every token of a rotation family (reuse-detection penalty)."""
    result = await session.execute(
        update(OIDCRefreshToken)
        .where(OIDCRefreshToken.family_id == family_id)
        .where(OIDCRefreshToken.status != REFRESH_STATUS_REVOKED)
        .values(status=REFRESH_STATUS_REVOKED)
    )
    await session.commit()
    return result.rowcount or 0


async def revoke_refresh_token(session: AsyncSession, token: OIDCRefreshToken) -> int:
    """RFC 7009 refresh revocation — the whole family falls to be safe."""
    return await revoke_family(session, token.family_id)


async def revoke_families_for_client(session: AsyncSession, client_id: str) -> int:
    result = await session.execute(
        update(OIDCRefreshToken)
        .where(OIDCRefreshToken.client_id == client_id)
        .where(OIDCRefreshToken.status != REFRESH_STATUS_REVOKED)
        .values(status=REFRESH_STATUS_REVOKED)
    )
    await session.commit()
    return result.rowcount or 0


# ---------------------------------------------------------------------------
# Signing keys (JWKS)
# ---------------------------------------------------------------------------


async def create_signing_key(session: AsyncSession, data: dict[str, Any]) -> OIDCSigningKey:
    key = OIDCSigningKey(**data)
    session.add(key)
    await session.commit()
    await session.refresh(key)
    return key


async def get_active_signing_key(session: AsyncSession) -> OIDCSigningKey | None:
    stmt = (
        select(OIDCSigningKey)
        .where(OIDCSigningKey.status == KEY_STATUS_ACTIVE)
        .order_by(OIDCSigningKey.created_at.desc())
        .limit(1)
    )
    return (await session.execute(stmt)).scalar_one_or_none()


async def list_active_signing_keys(session: AsyncSession) -> list[OIDCSigningKey]:
    """Keys currently in signing position (rotation reports the demoted set from here)."""
    stmt = select(OIDCSigningKey).where(OIDCSigningKey.status == KEY_STATUS_ACTIVE)
    return list((await session.execute(stmt)).scalars().all())


async def rotate_signing_keys(
    session: AsyncSession, *, new_key_data: dict[str, Any], retires_at: datetime | None
) -> OIDCSigningKey:
    """Insert the new ``active`` key and sweep-demote every OTHER active key to
    ``verify_only`` with the same retirement deadline — one commit, so the
    single-active invariant holds even under concurrent rotations (and is
    DB-enforced by the partial unique index from v2.30.0).
    """
    await session.execute(
        update(OIDCSigningKey)
        .where(OIDCSigningKey.status == KEY_STATUS_ACTIVE)
        .where(OIDCSigningKey.kid != new_key_data["kid"])
        .values(status=KEY_STATUS_VERIFY_ONLY, retires_at=retires_at)
    )
    key = OIDCSigningKey(**new_key_data)
    session.add(key)
    await session.commit()
    await session.refresh(key)
    return key


async def get_signing_key_by_kid(session: AsyncSession, kid: str) -> OIDCSigningKey | None:
    stmt = select(OIDCSigningKey).where(OIDCSigningKey.kid == kid)
    return (await session.execute(stmt)).scalar_one_or_none()


async def list_publishable_keys(session: AsyncSession, now: datetime) -> list[OIDCSigningKey]:
    """Keys whose public halves belong in JWKS: active, or verify-only not yet retired."""
    stmt = select(OIDCSigningKey).where(
        (OIDCSigningKey.status == KEY_STATUS_ACTIVE)
        | (
            (OIDCSigningKey.status == KEY_STATUS_VERIFY_ONLY)
            & (OIDCSigningKey.retires_at.is_(None) | (OIDCSigningKey.retires_at > now))
        )
    )
    return list((await session.execute(stmt)).scalars().all())