# pyright: reportMissingImports=false, reportUnknownVariableType=false

"""
swx-core OIDC identity provider (SWX-IDM-001)
---------------------------------------------
First-class OpenID Connect provider module. See
``docs/04-core-concepts/IDENTITY_PROVIDER.md`` for flows, claims, and hardening.

Module layout (CSR within the framework module):
- ``models``         — tables + schemas
- ``repositories``   — session-explicit data access
- ``admin``          — client management service (admin domain)
- ``security``       — PKCE / redirect matching / client authentication (P3)
- ``keys``           — signing keys + JWKS (P2)
- ``tokens``         — id_token/access minting + refresh families (P4)
- ``grant_service``  — authorize/token/userinfo/revocation logic (P3–P4)
- ``phone_verification`` — pluggable phone verification hook (P5)
- ``identity_linking``   — external-subject linking/resolution over swx_social_accounts (D-7)
- ``routers``        — ``issuer_router`` + ``admin_router`` (piped into app via route shims)
- ``cli``            — ``swx idp`` command group (P2)
"""

from swx_core.auth.oidc_provider.identity_linking import (
    link_external_identity,
    resolve_user_by_idp_sub,
)
from swx_core.auth.oidc_provider.models import (
    KEY_STATUS_ACTIVE,
    KEY_STATUS_VERIFY_ONLY,
    OIDCClient,
    OIDCClientCreate,
    OIDCClientPublic,
    OIDCClientUpdate,
    OIDCConsent,
    OIDCConsentCreate,
    OIDCConsentPublic,
    OIDCGrantCode,
    OIDCGrantCodePublic,
    OIDCRefreshToken,
    OIDCRefreshTokenPublic,
    OIDCSigningKey,
    OIDCSigningKeyCreate,
    OIDCSigningKeyPublic,
    REFRESH_STATUS_ACTIVE,
    REFRESH_STATUS_REVOKED,
    REFRESH_STATUS_ROTATED,
)

__all__ = [
    "KEY_STATUS_ACTIVE",
    "KEY_STATUS_VERIFY_ONLY",
    "OIDCClient",
    "OIDCClientCreate",
    "OIDCClientPublic",
    "OIDCClientUpdate",
    "OIDCConsent",
    "OIDCConsentCreate",
    "OIDCConsentPublic",
    "OIDCGrantCode",
    "OIDCGrantCodePublic",
    "OIDCRefreshToken",
    "OIDCRefreshTokenPublic",
    "OIDCSigningKey",
    "OIDCSigningKeyCreate",
    "OIDCSigningKeyPublic",
    "REFRESH_STATUS_ACTIVE",
    "REFRESH_STATUS_REVOKED",
    "REFRESH_STATUS_ROTATED",
    "link_external_identity",
    "resolve_user_by_idp_sub",
]