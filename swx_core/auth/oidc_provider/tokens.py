# pyright: reportMissingImports=false, reportAny=false, reportExplicitAny=false, reportUnknownMemberType=false, reportUnknownArgumentType=false, reportUnusedCallResult=false, reportAttributeAccessIssue=false

"""
OIDC token issuance (SWX-IDM-001, D-4/D-5)
------------------------------------------
- Signing: asymmetric (RS256 default, EdDSA supported) with a ``kid`` JOSE
  header, via the active key from ``swx_oidc_signing_keys``. HS256 is never used.
- Access tokens carry aud ``oidc_client:<client_id>`` so they can never be
  consumed as platform tokens, and platform tokens never pass as OIDC tokens
  (audience separation; platform machinery untouched — additive only).
- Refresh tokens are random 48-byte urlsafe values; only their SHA-256 hash is
  stored, inside a rotation family.
- id_token: OIDC Core claims ``iss sub aud exp iat auth_time nonce azp at_hash
  amr acr``; ``at_hash`` covers the pair's access token.
"""

import hashlib
import secrets
import uuid
from base64 import urlsafe_b64encode
from datetime import datetime, timedelta
from typing import Any

import jwt as pyjwt

from swx_core.auth.oidc_provider import repositories as oidc_repo
from swx_core.auth.oidc_provider.models import REFRESH_STATUS_ACTIVE
from swx_core.utils.time import utc_now

TOKEN_TYPE_BEARER = "Bearer"
_AUTH_PROVIDER = "oidc"


class OIDCSigningUnavailable(RuntimeError):
    """Fail-closed: issuance refuses when the issuer has no active signing key."""


def generate_refresh_value() -> tuple[str, str]:
    """Fresh random refresh token → ``(value, sha256_hash)``; only the hash is stored."""
    value = secrets.token_urlsafe(48)
    return value, sha256_hex(value)


def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _at_hash(access_token: str) -> str:
    """OIDC Core at_hash: left half of the SHA-256 digest of the access token."""
    digest = hashlib.sha256(access_token.encode()).digest()
    return urlsafe_b64encode(digest[: len(digest) // 2]).rstrip(b"=").decode()


async def _active_signing_material(session: Any) -> tuple[str, str, str]:
    key = await oidc_repo.get_active_signing_key(session)
    if key is None:
        raise OIDCSigningUnavailable("No active OIDC signing key — run `swx idp rotate-keys` first")
    from swx_core.security.encryption import decrypt_value

    return key.kid, key.algorithm, decrypt_value(key.private_key_encrypted)


async def mint_access_token(
    session: Any,
    *,
    issuer: str,
    subject: str,
    client_id: str,
    scope: str,
    expires_delta: timedelta,
    extra_claims: dict[str, Any] | None = None,
) -> str:
    kid, algorithm, private_pem = await _active_signing_material(session)
    now = datetime.now(tz=utc_now().tzinfo)
    claims: dict[str, Any] = {
        "iss": issuer,
        "sub": subject,
        "aud": f"oidc_client:{client_id}",
        "exp": (now + expires_delta).timestamp(),
        "iat": now.timestamp(),
        "jti": uuid.uuid4().hex,
        "scope": scope,
        "client_id": client_id,
        "auth_provider": _AUTH_PROVIDER,
    }
    if extra_claims:
        claims.update({key: value for key, value in extra_claims.items() if value is not None})
    return pyjwt.encode(claims, private_pem, algorithm=algorithm, headers={"kid": kid})


async def mint_id_token(
    session: Any,
    *,
    issuer: str,
    subject: str,
    client_id: str,
    expires_delta: timedelta,
    nonce: str | None = None,
    auth_time: datetime | None = None,
    acr: str | None = None,
    amr: list[str] | None = None,
    access_token: str | None = None,
) -> str:
    kid, algorithm, private_pem = await _active_signing_material(session)
    now = datetime.now(tz=utc_now().tzinfo)
    claims: dict[str, Any] = {
        "iss": issuer,
        "sub": subject,
        "aud": client_id,
        "exp": (now + expires_delta).timestamp(),
        "iat": now.timestamp(),
        "azp": client_id,
    }
    if auth_time is not None:
        claims["auth_time"] = auth_time.timestamp()
    if nonce:
        claims["nonce"] = nonce
    if acr:
        claims["acr"] = acr
    if amr:
        claims["amr"] = amr
    if access_token:
        claims["at_hash"] = _at_hash(access_token)
    return pyjwt.encode(claims, private_pem, algorithm=algorithm, headers={"kid": kid})


async def mint_refresh_token(
    session: Any,
    *,
    family_id: uuid.UUID,
    client_id: str,
    user_id: uuid.UUID,
    scope: str,
    auth_time: datetime | None,
    expires_delta: timedelta,
) -> tuple[str, Any]:
    """Generate a fresh refresh token in the given rotation family; store only its hash."""
    token = secrets.token_urlsafe(48)
    now = utc_now()
    row = await oidc_repo.create_refresh_token(
        session,
        {
            "family_id": family_id,
            "token_hash": sha256_hex(token),
            "client_id": client_id,
            "user_id": user_id,
            "scope": scope,
            "status": REFRESH_STATUS_ACTIVE,
            "auth_time": auth_time,
            "expires_at": now + expires_delta,
        },
    )
    return token, row


async def verify_oidc_access_token(session: Any, token: str) -> dict[str, Any]:
    """Verify signature (kid → our keys) and expiry. Audience is enforced by callers."""
    header = pyjwt.get_unverified_header(token)
    kid = header.get("kid")
    if not kid:
        raise pyjwt.InvalidTokenError("Missing kid header")
    resolved = await oidc_keys_resolve(session, kid)
    if resolved is None:
        raise pyjwt.InvalidTokenError(f"Unknown key id: {kid}")
    public_key, algorithm = resolved
    return pyjwt.decode(
        token,
        public_key,
        algorithms=[algorithm],
        options={"verify_aud": False},
    )


async def oidc_keys_resolve(session: Any, kid: str) -> tuple[Any, str] | None:
    from swx_core.auth.oidc_provider.keys import resolve_verification_key

    return await resolve_verification_key(session, kid)