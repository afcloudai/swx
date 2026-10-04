"""Password-reset token revocation registry.

Bridges password-reset tokens (JWTs addressed by ``jti``) onto the shared
token blacklist. Revocation entries are keyed by jti and, as a fallback
for tokens minted before ``jti`` existed, by ``user:<email>``.

All methods are best-effort: callers (``verify_password_reset_token``,
``revoke_password_reset_tokens``) handle connectivity failures inline.
"""

from typing import Any, Optional

_RESET_TOKEN_HASH_PREFIX = "pwd_reset_token:"


def _get_blacklist():
    try:
        from swx_core.container.container import get_container
        container = get_container()
        if container.bound("auth.token_blacklist"):
            return container.make("auth.token_blacklist")
    except Exception:
        pass
    return None


def _token_jti(decoded_token: dict[str, Any]) -> Optional[str]:
    return decoded_token.get("jti")


def _token_exp_ttl(decoded_token: dict[str, Any]) -> int:
    exp = decoded_token.get("exp")
    if exp is None:
        return 0
    from swx_core.utils.time import utc_now

    remaining = int(exp - utc_now().timestamp())
    return max(remaining, 1)


async def is_reset_token_revoked(token: str, decoded_token: dict[str, Any]) -> bool:
    """Return True when this reset token (or all tokens for its user) is revoked."""
    blacklist = _get_blacklist()
    if blacklist is None:
        return False

    jti = _token_jti(decoded_token)
    if jti and await blacklist.is_revoked_by_jti(jti):
        return True

    email = decoded_token.get("sub")
    if not email:
        return False

    try:
        import datetime

        iat = datetime.datetime.fromtimestamp(decoded_token["iat"], tz=datetime.timezone.utc)
    except (KeyError, ValueError, TypeError, OSError):
        return False

    return await blacklist.is_user_revoked(email, iat)


async def revoke_reset_token(token: str, decoded_token: dict[str, Any]) -> None:
    """Revoke a single reset token by jti (or full-string hash fallback)."""
    blacklist = _get_blacklist()
    if blacklist is None:
        return

    jti = _token_jti(decoded_token)
    if jti:
        await blacklist.revoke(jti, _token_exp_ttl(decoded_token))
        return

    import hashlib

    hashed = hashlib.sha256(token.encode()).hexdigest()
    await blacklist.revoke(f"{_RESET_TOKEN_HASH_PREFIX}{hashed}", _token_exp_ttl(decoded_token))


async def revoke_user_reset_tokens(
    email: str, ttl_seconds: int = 172800
) -> bool:
    """Revoke every outstanding reset token for a user.

    Uses the blacklist's user-level revocation (email-keyed); check-side
    compares the token's ``iat`` against the revocation timestamp.

    Returns:
        True if a registry was available to record the revocation.
    """
    blacklist = _get_blacklist()
    if blacklist is None:
        return False
    await blacklist.revoke_user_tokens(email, ttl_seconds=ttl_seconds)
    return True