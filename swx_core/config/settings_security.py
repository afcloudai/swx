# pyright: reportUnknownVariableType=false, reportUnknownArgumentType=false

"""
Security & Authentication Settings Mixin.

Defines security configuration: token algorithms, secret keys, expiry
durations, MFA, email verification, social account linking, and account
lockout controls.

Secret-key policy: SECRET_KEY, REFRESH_SECRET_KEY, and
PASSWORD_RESET_SECRET_KEY may be None during validation. A model validator
*fails settings load* when any of them is unset outside development
environments (``local``/``development``/``dev``/``test``/``testing``) — a
silently self-generated per-process secret invalidates all tokens on
restart and diverges across workers. In development an unset key resolves
to a random per-process value so local boot needs no .env.
"""

import secrets
from typing import Literal, Optional

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings

_DEVELOPMENT_ENVIRONMENTS = ("local", "development", "dev", "test", "testing")

_SECRET_FIELDS = ("SECRET_KEY", "REFRESH_SECRET_KEY", "PASSWORD_RESET_SECRET_KEY")


class SecuritySettingsMixin(BaseSettings):
    """Security and authentication configuration."""

    # Security & Authentication
    PASSWORD_SECURITY_ALGORITHM: str = Field(
        default="HS256", description="Algorithm for password security"
    )
    SECRET_KEY: Optional[str] = Field(
        default=None,
        description="Secret key for JWT tokens (required outside development)",
    )
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    REFRESH_TOKEN_EXPIRE_DAYS: int = 30
    MFA_CHALLENGE_EXPIRE_MINUTES: int = 5
    EMAIL_VERIFICATION_ENABLED: bool = True
    EMAIL_VERIFICATION_TOKEN_EXPIRE_HOURS: int = 24
    SOCIAL_ACCOUNT_LINKING_ENABLED: bool = True
    REFRESH_SECRET_KEY: Optional[str] = Field(
        default=None,
        description="Secret key for refresh tokens (required outside development)",
    )
    PASSWORD_RESET_SECRET_KEY: Optional[str] = Field(
        default=None,
        description="Secret key for password reset tokens (required outside development)",
    )

    @model_validator(mode="after")
    def _validate_secret_keys_outside_development(self):
        """Fail settings load when secrets are unset outside development."""
        environment = getattr(self, "ENVIRONMENT", "local")
        if environment in _DEVELOPMENT_ENVIRONMENTS:
            return self

        unset = [name for name in _SECRET_FIELDS if not getattr(self, name)]
        if unset:
            raise ValueError(
                f"{', '.join(unset)} must be set explicitly via environment in "
                f"ENVIRONMENT={environment!r}. Self-generated per-process secrets "
                f"break multi-worker deployments and invalidate all tokens on restart."
            )
        return self

    def model_post_init(self, __context) -> None:
        # Development fallback: fill unset keys with a random per-process value so
        # local boot needs no .env. In staging/production the validator has already
        # guaranteed explicit values, so this only handles the dev case. Idempotent
        # under pydantic-settings' revalidation of this hook.
        if getattr(self, "ENVIRONMENT", "local") not in _DEVELOPMENT_ENVIRONMENTS:
            return
        for name in _SECRET_FIELDS:
            if getattr(self, name) is None:
                object.__setattr__(self, name, secrets.token_urlsafe(32))

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
