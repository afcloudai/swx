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

    @model_validator(mode="after")
    def _validate_oidc_issuer_outside_development(self):
        """Fail settings load when the OIDC issuer is unset outside development.

        IDP-008 gate (M-2): an unset issuer is derived from ``request.base_url``,
        so Host headers could poison the discovery document and token audiences.
        Production must pin the issuer explicitly.
        """
        environment = getattr(self, "ENVIRONMENT", "local")
        if environment in _DEVELOPMENT_ENVIRONMENTS:
            return self

        if not getattr(self, "SWX_OIDC_ISSUER", None):
            raise ValueError(
                "SWX_OIDC_ISSUER must be set explicitly (e.g. https://auth.example.com) in "
                f"ENVIRONMENT={environment!r}: a request-derived issuer lets Host headers "
                "poison the OIDC discovery document and token audiences."
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

    # OIDC identity provider (SWX-IDM-001)
    SWX_OIDC_ISSUER: Optional[str] = Field(
        default=None,
        description=(
            "Absolute issuer URL (e.g. https://auth.afcloudai.com). "
            "When unset, derived from the request base URL + ROUTE_PREFIX."
        ),
    )
    SWX_OIDC_LOGIN_URL: str = Field(
        default="/auth/cookie/login",
        description=(
            "Where /oidc/authorize redirects unauthenticated users to authenticate; "
            "the IdP app UI mounts here and redirects back to the authorize URL."
        ),
    )
    SWX_OIDC_CODE_TTL_SECONDS: int = Field(default=60, description="Authorization-code TTL (single use)")
    SWX_OIDC_ID_TOKEN_TTL_SECONDS: int = Field(default=3600, description="id_token TTL")
    SWX_OIDC_ACCESS_TTL_SECONDS: int = Field(default=3600, description="OIDC access-token TTL")
    SWX_OIDC_REFRESH_TTL_SECONDS: int = Field(default=1209600, description="OIDC refresh-token TTL")
    SWX_OIDC_KEY_RETIREMENT_DAYS: int = Field(
        default=30, description="Days a demoted signing key stays verify-only before retirement"
    )
    SWX_OIDC_DEFAULT_SIGNING_ALGORITHM: str = Field(
        default="RS256", description="Default id_token signing algorithm (RS256 or EdDSA)"
    )
    SWX_PHONE_VERIFICATION_CHANNEL: Optional[str] = Field(
        default=None,
        description=(
            "Registered PhoneVerificationChannel name for phone-verification OTP delivery "
            "(register via register_phone_channel(); default logs the code — no transport configured)."
        ),
    )
    SWX_EMAIL_OTP_CHANNEL: Optional[str] = Field(
        default=None,
        description=(
            "Registered EmailOtpChannel name for email-verification/dual OTP delivery "
            "(register via the identity_verification registry; default logs the code; "
            "the estate plugs its SMTP/SendGrid channel at bootstrap)."
        ),
    )
    SWX_IDENTITY_REQUIRED_VERIFICATIONS: Literal["none", "phone", "email", "both"] = Field(
        default="none",
        description=(
            "Identity gate for the OIDC login flow: 'none' issues freely; 'phone'/'email' "
            "require that channel to be verified (phone_verified_at / email_verified_at); "
            "'both' sends OTP to BOTH channels (dual delivery) and requires both confirmed "
            "before /oidc/authorize issues — gate is fail-closed (interaction_required)."
        ),
    )
