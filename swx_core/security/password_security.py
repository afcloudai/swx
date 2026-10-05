"""
Password Security & Token Management
------------------------------------
This module provides:
- **Password hashing & verification** using bcrypt.
- **JWT-based password reset token generation & validation.**
- **Security mechanisms for handling authentication safely.**

Key Functions:
- `verify_password()`: Check if a plaintext password matches a hashed password.
- `get_password_hash()`: Hash a password securely.
- `generate_password_reset_token()`: Create a JWT token for password reset.
- `verify_password_reset_token()`: Validate and decode a password reset token.

"""

import asyncio
from datetime import datetime, timedelta, timezone

import jwt
from jwt.exceptions import ExpiredSignatureError, InvalidTokenError
from passlib.context import CryptContext
from sqlalchemy.ext.asyncio import AsyncSession

from swx_core.config.settings import settings

# Password hashing context (bcrypt)
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


async def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify a plaintext password against a securely hashed password.
    Runs the blocking verify operation in a threadpool to avoid blocking the event loop.

    Args:
        plain_password (str): The user-provided plaintext password.
        hashed_password (str): The stored bcrypt-hashed password.

    Returns:
        bool: True if the password is valid, False otherwise.
    """
    return await asyncio.to_thread(pwd_context.verify, plain_password, hashed_password)


async def get_password_hash(password: str) -> str:
    """
    Hash a password securely using bcrypt.
    Runs the blocking hash operation in a threadpool to avoid blocking the event loop.

    Args:
        password (str): The plaintext password.

    Returns:
        str: The hashed password.
    """
    return await asyncio.to_thread(pwd_context.hash, password)


async def generate_password_reset_token(
    session: AsyncSession,
    email: str,
    auth_provider: str = "local",
) -> str | None:
    """
    Generate a JWT token for password reset.

    This function uses a separate secret key and explicit audience to prevent
    token type confusion with access tokens.

    This function is only available for users with `auth_provider = local` (i.e., not social login users).

    Args:
        session: Database session for settings access
        email (str): The email address associated with the user.
        auth_provider (str, optional): The authentication provider. Defaults to `"local"`.

    Returns:
        str | None: A JWT reset token, or None if the user uses a social login provider.
    """
    if auth_provider != "local":
        return None  # Social login users should reset passwords via their provider.

    # Set token expiration time from settings (DB -> .env -> default)
    from swx_core.services.settings_helper import get_token_expiration
    from swx_core.auth.core.jwt import create_token, TokenAudience

    expires_delta = await get_token_expiration(session, "password_reset")

    # Create token with explicit audience and separate secret key.
    # The jti claim (added by create_token) makes this token addressable
    # by the token blacklist, so outstanding reset links are revocable.
    return create_token(
        subject=email,
        audience=TokenAudience.USER,  # Password reset is for user domain
        expires_delta=expires_delta,
        auth_provider="local",
        secret_key=settings.PASSWORD_RESET_SECRET_KEY,  # Separate secret for reset tokens
    )


async def verify_password_reset_token(token: str, check_blacklist: bool = True) -> str | None:
    """
    Verify and decode a password reset token.

    This function validates the token using the separate password reset secret key
    and ensures it has the correct audience. When the token carries a ``jti``,
    it is additionally checked against the token blacklist so revoked reset
    links are rejected.

    Args:
        token (str): The JWT reset token.
        check_blacklist (bool): Consult the revocation registry (default True).
            Leave enabled in request paths; disable only for offline tooling.

    Returns:
        str | None: The email associated with the reset token if valid, otherwise None.
    """
    try:
        from swx_core.auth.core.jwt import decode_token, TokenAudience

        # Decode token using separate secret key and validate audience
        decoded_token = decode_token(
            token,
            TokenAudience.USER,
            secret_key=settings.PASSWORD_RESET_SECRET_KEY,
        )

    except (ExpiredSignatureError, InvalidTokenError, jwt.InvalidAudienceError):
        return None  # Invalid or expired token

    if check_blacklist and await _reset_token_revoked(token, decoded_token):
        return None

    # Return the email stored in the token
    return str(decoded_token["sub"])


async def _reset_token_revoked(token: str, decoded_token: dict) -> bool:
    """Check reset-token revocation via jti or fallback user-level entries."""
    from swx_core.security.password_reset_registry import is_reset_token_revoked

    try:
        return await is_reset_token_revoked(token, decoded_token)
    except Exception:
        # Fail closed on registry outages: an unverifiable revocation state
        # must not grant a password change.
        return True
