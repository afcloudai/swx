# pyright: reportUnknownVariableType=false, reportUnknownArgumentType=false

"""
Security & Authentication Settings Mixin.

Defines security configuration: token algorithms, secret keys, expiry
durations, MFA, email verification, social account linking, and account
lockout controls.
"""

import secrets
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings


class SecuritySettingsMixin(BaseSettings):
    """Security and authentication configuration."""

    # Security & Authentication
    PASSWORD_SECURITY_ALGORITHM: str = Field(
        default="HS256", description="Algorithm for password security"
    )
    SECRET_KEY: str = Field(
        default_factory=lambda: secrets.token_urlsafe(32),
        description="Secret key for JWT tokens",
    )
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    REFRESH_TOKEN_EXPIRE_DAYS: int = 30  # 30 days
    MFA_CHALLENGE_EXPIRE_MINUTES: int = 5
    EMAIL_VERIFICATION_ENABLED: bool = True
    EMAIL_VERIFICATION_TOKEN_EXPIRE_HOURS: int = 24
    SOCIAL_ACCOUNT_LINKING_ENABLED: bool = True
    REFRESH_SECRET_KEY: str = Field(
        default_factory=lambda: secrets.token_urlsafe(32),
        description="Secret key for refresh tokens",
    )
    PASSWORD_RESET_SECRET_KEY: str = Field(
        default_factory=lambda: secrets.token_urlsafe(32),
        description="Secret key for password reset tokens (separate from access tokens)",
    )

    # Session Cookie (Starlette SessionMiddleware — SOC 2 CC6.1)
    SESSION_MAX_AGE: int = Field(
        default=86400,
        description="Session cookie lifetime in seconds (default 1 day)",
    )
    SESSION_SAME_SITE: Literal["lax", "strict", "none"] = Field(
        default="lax",
        description="Session cookie SameSite policy",
    )
    HTTPS_ONLY: bool | None = Field(
        default=None,
        description=(
            "Set the Secure flag on the session cookie. "
            "Default (None) derives from ENVIRONMENT: True in production/staging, False locally."
        ),
    )
