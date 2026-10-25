# pyright: reportAny=false, reportExplicitAny=false, reportUnknownMemberType=false, reportUnknownArgumentType=false, reportMissingImports=false, reportUnusedCallResult=false, reportAttributeAccessIssue=false

"""
Unit tests for SWX-IDM-001 D-4 (signing keys, JWKS, discovery) and the
admin-surface idp:clients:* enforcement (v2_30_2 fix).
"""

import uuid
from datetime import timedelta
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import jwt
import pytest

from swx_core.auth.oidc_provider import keys as oidc_keys
from swx_core.auth.oidc_provider import repositories as oidc_repo
from swx_core.auth.oidc_provider.grant_service import derive_issuer as _derive_issuer
from swx_core.auth.oidc_provider.models import OIDCSigningKey
from swx_core.auth.oidc_provider.routers import (
    issuer_router,
    openid_configuration,
    require_oidc_clients_permission,
)
from swx_core.config.settings import settings
from swx_core.models.admin_user import AdminUser
from swx_core.models.social_account import SocialAccount
from swx_core.security import encryption as encryption_module
from swx_core.services.audit_logger import AuditAction
from swx_core.utils.time import utc_now

pytestmark = pytest.mark.unit


def _key_row(**overrides: Any) -> OIDCSigningKey:
    data: dict[str, Any] = {
        "kid": uuid.uuid4().hex,
        "algorithm": "RS256",
        "private_key_encrypted": "v2:ciphertext",
        "public_jwk": {"kty": "RSA", "use": "sig", "alg": "RS256", "kid": "k", "n": "abc", "e": "AQAB"},
        "status": "active",
    }
    data.update(overrides)
    return OIDCSigningKey(**data)


class TestGenerateKeypair:
    def test_rs256_roundtrip_sign_verify_with_kid_header(self) -> None:
        kid, private_pem, jwk = oidc_keys.generate_keypair("RS256")

        assert jwk["kty"] == "RSA" and jwk["alg"] == "RS256" and jwk["kid"] == kid
        assert jwk["use"] == "sig" and "n" in jwk and "e" in jwk

        token = jwt.encode({"sub": "user-1"}, private_pem, algorithm="RS256", headers={"kid": kid})
        header = jwt.get_unverified_header(token)
        assert header["kid"] == kid and header["alg"] == "RS256"

        from cryptography.hazmat.primitives import serialization

        private = serialization.load_pem_private_key(private_pem.encode(), password=None)
        jwt.decode(token, private.public_key(), algorithms=["RS256"])  # signature verifies

    def test_eddsa_roundtrip(self) -> None:
        kid, private_pem, jwk = oidc_keys.generate_keypair("EdDSA")

        assert jwk["kty"] == "OKP" and jwk["crv"] == "Ed25519" and "x" in jwk

        token = jwt.encode({"sub": "user-1"}, private_pem, algorithm="EdDSA", headers={"kid": kid})
        from cryptography.hazmat.primitives import serialization

        private = serialization.load_pem_private_key(private_pem.encode(), password=None)
        jwt.decode(token, private.public_key(), algorithms=["EdDSA"])

    def test_unsupported_algorithm_refused(self) -> None:
        with pytest.raises(ValueError, match="Unsupported"):
            oidc_keys.generate_keypair("HS256")


class TestRotation:
    async def test_dry_run_persists_nothing(self) -> None:
        session = MagicMock()
        with patch.object(oidc_repo, "list_active_signing_keys", new=AsyncMock(return_value=[_key_row(kid="oldkid1")])):
            with patch.object(oidc_repo, "rotate_signing_keys", new=AsyncMock()) as rotate:
                result = await oidc_keys.rotate_signing_keys(session, algorithm="RS256", dry_run=True)

        rotate.assert_not_called()
        assert result["dry_run"] is True
        assert result["retired_kids"] == ["oldkid1"]

    async def test_rotation_persists_and_audits(self) -> None:
        session = MagicMock()
        with (
            patch.object(oidc_repo, "list_active_signing_keys", new=AsyncMock(return_value=[_key_row(kid="oldkid1")])),
            patch.object(oidc_keys, "AuditLogger") as audit_logger,
            patch.object(oidc_keys, "encrypt_value", return_value="v2:enc"),
        ):
            audit_logger.return_value.log_event = AsyncMock()

            def _rotate_side_effect(*args: Any, **kwargs: Any) -> OIDCSigningKey:
                return _key_row(kid=kwargs["new_key_data"]["kid"])

            rotate = AsyncMock(side_effect=_rotate_side_effect)
            with patch.object(oidc_repo, "rotate_signing_keys", new=rotate):
                result = await oidc_keys.rotate_signing_keys(session, algorithm="RS256", actor_id="cli:swx-idp")

                stored = rotate.call_args.kwargs["new_key_data"]
                assert stored["kid"] == result["new_kid"]
                assert stored["private_key_encrypted"] == "v2:enc"
                assert result["retired_kids"] == ["oldkid1"]
                assert result["dry_run"] is False
                assert audit_logger.return_value.log_event.call_args.kwargs["action"] == AuditAction.AUTH_OAUTH_KEY_ROTATED

    async def test_retirement_uses_settings_default(self) -> None:
        session = MagicMock()
        with (
            patch.object(oidc_repo, "list_active_signing_keys", new=AsyncMock(return_value=[])),
            patch.object(oidc_repo, "rotate_signing_keys", new=AsyncMock(return_value=_key_row())),
            patch.object(oidc_keys, "AuditLogger") as audit_logger,
            patch.object(oidc_keys, "encrypt_value", return_value="e"),
        ):
            audit_logger.return_value.log_event = AsyncMock()
            result = await oidc_keys.rotate_signing_keys(session, algorithm="EdDSA")

        expected = utc_now() + timedelta(days=settings.SWX_OIDC_KEY_RETIREMENT_DAYS)
        assert abs((result["retires_at"] - expected).total_seconds()) < 5

    async def test_rejects_hs256(self) -> None:
        with pytest.raises(ValueError, match="Unsupported key algorithm"):
            await oidc_keys.rotate_signing_keys(MagicMock(), algorithm="HS256")


class TestJWKS:
    async def test_publishes_public_halves_only(self) -> None:
        rows = [
            _key_row(public_jwk={"kty": "RSA", "use": "sig", "alg": "RS256", "kid": "jwk1", "n": "a", "e": "AQAB"}),
            _key_row(status="verify_only", public_jwk={"kty": "RSA", "use": "sig", "alg": "RS256", "kid": "jwk2", "n": "b", "e": "AQAB"}),
        ]
        with patch.object(oidc_repo, "list_publishable_keys", new=AsyncMock(return_value=rows)):
            document = await oidc_keys.build_jwks(MagicMock())

        assert [k["kid"] for k in document["keys"]] == ["jwk1", "jwk2"]
        assert all("private" not in jwk for jwk in document["keys"])


def _request_with_base_url(base_url: str) -> MagicMock:
    request = MagicMock()
    request.base_url = base_url
    return request


class TestDiscovery:
    def test_issuer_derived_from_base_url_and_route_prefix(self) -> None:
        assert _derive_issuer(_request_with_base_url("https://idp.example.com/")) == "https://idp.example.com/api"

    def test_issuer_setting_overrides_derivation(self) -> None:
        with patch.object(settings, "SWX_OIDC_ISSUER", "https://auth.afcloudai.com"):
            assert _derive_issuer(_request_with_base_url("https://other.example.com/")) == "https://auth.afcloudai.com"

    async def test_discovery_document_shape(self) -> None:
        with patch.object(settings, "SWX_OIDC_ISSUER", "https://auth.afcloudai.com"):
            document = await openid_configuration(_request_with_base_url("https://x.example.com/"))

        assert document["issuer"] == "https://auth.afcloudai.com"
        assert document["authorization_endpoint"].endswith("/oidc/authorize")
        assert document["token_endpoint"].endswith("/oidc/token")
        assert document["jwks_uri"].endswith("/jwks.json")
        assert document["response_types_supported"] == ["code"]
        assert document["code_challenge_methods_supported"] == ["S256"]
        assert "password" not in document["grant_types_supported"]
        assert "phone" in document["claims_supported"] and "phone_verified" in document["claims_supported"]
        assert not any("email" in claim.lower() for claim in document["claims_supported"])
        assert set(document["id_token_signing_alg_values_supported"]) == {"EdDSA", "RS256"}

    def test_discovery_and_jwks_routes_exist(self) -> None:
        paths = [getattr(route, "path", "") for route in issuer_router.routes]
        assert "/.well-known/openid-configuration" in paths
        assert "/jwks.json" in paths


class TestResolveVerificationKey:
    async def _real_key_row(self, **overrides: Any) -> OIDCSigningKey:
        kid, pem, jwk = oidc_keys.generate_keypair("RS256")
        data = {"kid": kid, "algorithm": "RS256", "private_key_encrypted": pem, "public_jwk": jwk}
        data.update(overrides)
        return _key_row(**data)

    async def test_active_key_resolves(self) -> None:
        row = await self._real_key_row()
        with (
            patch.object(oidc_repo, "get_signing_key_by_kid", AsyncMock(return_value=row)),
            patch.object(encryption_module, "decrypt_value", new=lambda value: value),
        ):
            resolved = await oidc_keys.resolve_verification_key(MagicMock(), row.kid)

        assert resolved is not None and resolved[1] == "RS256"

    async def test_verify_only_unretired_key_resolves(self) -> None:
        row = await self._real_key_row(status="verify_only", retires_at=utc_now() + timedelta(days=10))
        with (
            patch.object(oidc_repo, "get_signing_key_by_kid", AsyncMock(return_value=row)),
            patch.object(encryption_module, "decrypt_value", new=lambda value: value),
        ):
            resolved = await oidc_keys.resolve_verification_key(MagicMock(), row.kid)

        assert resolved is not None

    async def test_retired_key_stops_verifying(self) -> None:
        """L-4: past retires_at ⇒ the kid stops verifying internally too."""
        row = await self._real_key_row(status="verify_only", retires_at=utc_now() - timedelta(days=1))
        with (
            patch.object(oidc_repo, "get_signing_key_by_kid", AsyncMock(return_value=row)),
            patch.object(encryption_module, "decrypt_value", new=lambda value: value),
        ):
            resolved = await oidc_keys.resolve_verification_key(MagicMock(), row.kid)

        assert resolved is None


class TestOidcIssuerProductionGate:
    def test_production_requires_explicit_issuer(self) -> None:
        """M-2: derived-from-request issuers are Host-header-poisonable — production must pin."""
        from swx_core.config.settings import Settings

        with pytest.raises(Exception, match="SWX_OIDC_ISSUER"):
            Settings(
                ENVIRONMENT="production",
                SECRET_KEY="s",
                REFRESH_SECRET_KEY="r",
                PASSWORD_RESET_SECRET_KEY="p",
                SWX_OIDC_ISSUER=None,
                _env_file=None,
            )

    def test_production_with_pinned_issuer_loads(self) -> None:
        from swx_core.config.settings import Settings

        configured = Settings(
            ENVIRONMENT="production",
            SECRET_KEY="s",
            REFRESH_SECRET_KEY="r",
            PASSWORD_RESET_SECRET_KEY="p",
            SWX_OIDC_ISSUER="https://auth.afcloudai.com",
            _env_file=None,
        )
        assert configured.SWX_OIDC_ISSUER == "https://auth.afcloudai.com"


class TestSocialAccountIdentityInvariant:
    def test_provider_identity_unique_constraint_declared(self) -> None:
        constraints = {
            getattr(item, "name", None)
            for item in SocialAccount.__table_args__
            if not isinstance(item, dict)
        }
        assert "uq_social_account_provider_identity" in constraints


class TestOidcClientsPermissionGate:
    async def test_denied_without_binding(self) -> None:
        admin = AdminUser(email="operator@example.com", is_active=True)
        checker = require_oidc_clients_permission("write")

        with patch(
            "swx_core.auth.oidc_provider.routers.has_admin_permission",
            new=AsyncMock(return_value=False),
        ) as has_perm:
            with patch("swx_core.auth.oidc_provider.routers.alert_engine") as alert_engine:
                alert_engine.emit = AsyncMock()
                with pytest.raises(Exception, match="idp:clients:write"):
                    await checker(admin_user=admin, session=MagicMock())

        assert has_perm.await_args.args[2] == "idp:clients:write"
        alert_engine.emit.assert_awaited_once()

    async def test_allowed_with_permission(self) -> None:
        admin = AdminUser(email="operator@example.com", is_active=True)
        checker = require_oidc_clients_permission("read")

        with patch(
            "swx_core.auth.oidc_provider.routers.has_admin_permission",
            new=AsyncMock(return_value=True),
        ):
            result = await checker(admin_user=admin, session=MagicMock())

        assert result is admin


class TestRootOperatorCarveOut:
    async def test_first_superuser_email_passes_without_binding(self) -> None:
        from swx_core.rbac.helpers import has_admin_permission

        admin = AdminUser(email=str(settings.FIRST_SUPERUSER), is_active=True)
        with patch("swx_core.rbac.helpers.get_admin_permissions", new=AsyncMock()) as get_perms:
            assert await has_admin_permission(MagicMock(), admin, "idp:clients:manage") is True
        get_perms.assert_not_awaited()

    async def test_other_admin_requires_binding(self) -> None:
        from swx_core.rbac.helpers import has_admin_permission

        admin = AdminUser(email="someone.else@example.com", is_active=True)
        with patch(
            "swx_core.rbac.helpers.get_admin_permissions",
            new=AsyncMock(return_value=[]),
        ):
            assert await has_admin_permission(MagicMock(), admin, "idp:clients:read") is False