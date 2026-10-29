# pyright: reportMissingImports=false, reportAny=false, reportExplicitAny=false, reportUnknownMemberType=false, reportUnknownArgumentType=false, reportUnusedCallResult=false

"""
OIDC signing key management (SWX-IDM-001, D-4)
----------------------------------------------
Asymmetric signing keys for the OIDC provider — RS256 (RSA-2048) by default,
EdDSA (Ed25519) optional. HS256 is never used for IdP tokens.

- Private PEM is encrypted at rest via ``swx_core.security.encryption``
  (``swx_oidc_signing_keys.private_key_encrypted``); it is never returned by
  any API surface.
- Rotation: the new key becomes the single ``active`` key; every previously
  active key is swept to ``verify_only`` with a retirement deadline, so tokens
  signed by older kids remain valid until they expire (or until retirement).
- JWKS (RFC 7517) publishes public halves of active + unretired verify-only keys.
"""

import base64
import uuid
from datetime import datetime, timedelta
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa

from swx_core.auth.oidc_provider import repositories as oidc_repo
from swx_core.auth.oidc_provider.models import KEY_STATUS_ACTIVE, KEY_STATUS_VERIFY_ONLY
from swx_core.config.settings import settings
from swx_core.security.encryption import encrypt_value
from swx_core.services.audit_logger import ActorType, AuditAction, AuditLogger, AuditOutcome
from swx_core.utils.time import utc_now

SUPPORTED_KEY_ALGORITHMS = frozenset({"RS256", "EdDSA"})


def _b64url_uint(value: int) -> str:
    byte_length = (value.bit_length() + 7) // 8
    return base64.urlsafe_b64encode(value.to_bytes(byte_length, "big")).rstrip(b"=").decode()


def _pem_public_rsa_jwk(private_key: rsa.RSAPrivateKey, kid: str) -> dict[str, Any]:
    numbers = private_key.public_key().public_numbers()
    return {
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": kid,
        "n": _b64url_uint(numbers.n),
        "e": _b64url_uint(numbers.e),
    }


def _raw_public_ed25519_jwk(private_key: ed25519.Ed25519PrivateKey, kid: str) -> dict[str, Any]:
    raw = private_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return {
        "kty": "OKP",
        "use": "sig",
        "alg": "EdDSA",
        "kid": kid,
        "crv": "Ed25519",
        "x": base64.urlsafe_b64encode(raw).rstrip(b"=").decode(),
    }


def generate_keypair(algorithm: str) -> tuple[str, str, dict[str, Any]]:
    """Generate a keypair → ``(kid, private_pem, public_jwk)``."""
    if algorithm not in SUPPORTED_KEY_ALGORITHMS:
        raise ValueError(f"Unsupported key algorithm: {algorithm}")
    kid = uuid.uuid4().hex
    if algorithm == "RS256":
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        jwk = _pem_public_rsa_jwk(private_key, kid)
    else:
        private_key = ed25519.Ed25519PrivateKey.generate()
        jwk = _raw_public_ed25519_jwk(private_key, kid)
    private_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    return kid, private_pem, jwk


async def rotate_signing_keys(
    session: Any,
    *,
    algorithm: str = "RS256",
    retirement_days: int | None = None,
    dry_run: bool = False,
    actor_id: str | None = None,
) -> dict[str, Any]:
    """Rotate to a fresh signing key.

    The new key becomes the only ``active`` key; all previously active keys are
    demoted to ``verify_only`` until ``retires_at`` (default:
    ``SWX_OIDC_KEY_RETIREMENT_DAYS``). ``dry_run`` reports the change without
    persisting anything.
    """
    if algorithm not in SUPPORTED_KEY_ALGORITHMS:
        raise ValueError(f"Unsupported key algorithm: {algorithm} (allowed: {sorted(SUPPORTED_KEY_ALGORITHMS)})")

    previously_active = await oidc_repo.list_active_signing_keys(session)
    kid, private_pem, public_jwk = generate_keypair(algorithm)

    if dry_run:
        return {
            "dry_run": True,
            "algorithm": algorithm,
            "new_kid": kid,
            "retired_kids": [key.kid for key in previously_active],
        }

    days = retirement_days if retirement_days is not None else settings.SWX_OIDC_KEY_RETIREMENT_DAYS
    if days <= 0:
        raise ValueError("retirement_days must be positive")
    retires_at: datetime = utc_now() + timedelta(days=days)

    key = await oidc_repo.rotate_signing_keys(
        session,
        new_key_data={
            "kid": kid,
            "algorithm": algorithm,
            "private_key_encrypted": encrypt_value(private_pem),
            "public_jwk": public_jwk,
            "status": KEY_STATUS_ACTIVE,
        },
        retires_at=retires_at,
    )
    retired_kids = [existing.kid for existing in previously_active if existing.kid != key.kid]

    await AuditLogger(session).log_event(
        action=AuditAction.AUTH_OAUTH_KEY_ROTATED,
        actor_type=ActorType.SYSTEM,
        actor_id=actor_id,
        resource_type="oidc_signing_key",
        resource_id=key.kid,
        outcome=AuditOutcome.SUCCESS,
        context={"algorithm": algorithm, "retired_kids": retired_kids, "retires_at": retires_at.isoformat()},
    )

    return {
        "dry_run": False,
        "algorithm": algorithm,
        "new_kid": key.kid,
        "retired_kids": retired_kids,
        "retires_at": retires_at,
    }


async def build_jwks(session: Any) -> dict[str, Any]:
    """RFC 7517 JWKS document: public halves of publishable (active / verify-only) keys."""
    publishable = await oidc_repo.list_publishable_keys(session, utc_now())
    return {"keys": [key.public_jwk for key in publishable]}


def load_private_key(private_key_encrypted: str) -> Any:
    """Decrypt + parse the private key for signing (tokens module, P4)."""
    from swx_core.security.encryption import decrypt_value

    pem = decrypt_value(private_key_encrypted)
    return serialization.load_pem_private_key(pem.encode(), password=None)


async def resolve_verification_key(session: Any, kid: str) -> tuple[Any, str] | None:
    """Public verification key for a known ``kid`` → ``(public_key, algorithm)``, or None.

    Retired keys stop verifying internally at their ``retires_at`` deadline —
    consistent with JWKS dropping them (IDP-008 L-4).
    """
    key = await oidc_repo.get_signing_key_by_kid(session, kid)
    if key is None:
        return None
    if key.status not in (KEY_STATUS_ACTIVE, KEY_STATUS_VERIFY_ONLY):
        return None
    if key.status == KEY_STATUS_VERIFY_ONLY and key.retires_at is not None and key.retires_at <= utc_now():
        return None
    private_key = load_private_key(key.private_key_encrypted)
    return private_key.public_key(), key.algorithm