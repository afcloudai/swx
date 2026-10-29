# pyright: reportAny=false, reportExplicitAny=false, reportUnknownMemberType=false, reportUnknownArgumentType=false, reportMissingImports=false, reportUnusedCallResult=false

"""
Unit tests for SWX-IDM-001 D-2: OIDC client models, validation, and admin service.
"""

import re
import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from swx_core.auth.oidc_provider import admin as oidc_admin
from swx_core.auth.oidc_provider.models import (
    OIDCClient,
    OIDCClientCreate,
    OIDCClientPublic,
    OIDCClientUpdate,
)
from swx_core.routes.admin.oidc_route import router as admin_oidc_router
from swx_core.services.audit_logger import AuditAction

pytestmark = pytest.mark.unit


def _sample_create(**overrides: object) -> OIDCClientCreate:
    data: dict[str, object] = {
        "name": "Business Console",
        "redirect_uris": ["https://console.example.com/callback"],
    }
    data.update(overrides)
    return OIDCClientCreate.model_validate(data)


def _client_row(**overrides: object) -> OIDCClient:
    data: dict[str, object] = {
        "name": "Business Console",
        "client_id": "aabbccddeeff00112233445566778899",
        "client_secret_hash": "$2b$12$abc",
        "redirect_uris": ["https://console.example.com/callback"],
        "grant_types": ["authorization_code", "refresh_token"],
        "scopes": ["openid", "profile", "phone"],
    }
    data.update(overrides)
    return OIDCClient(**data)


class TestOIDCClientSchemas:
    def test_public_schema_never_exposes_secret_hash(self) -> None:
        public = OIDCClientPublic.model_validate(
            _client_row().model_dump() | {"has_client_secret": True}
        )
        assert "client_secret_hash" not in public.model_dump()
        assert public.has_client_secret is True

    def test_public_schema_reports_secretless_client(self) -> None:
        row = _client_row(client_secret_hash=None)
        public = OIDCClientPublic.model_validate(row.model_dump() | {"has_client_secret": False})
        assert public.has_client_secret is False

    def test_create_requires_redirect_uris(self) -> None:
        with pytest.raises(Exception, match="redirect_uris"):
            OIDCClientCreate.model_validate({"name": "x", "redirect_uris": []})

    def test_model_defaults_apply(self) -> None:
        row = _client_row()
        assert row.enabled is True
        assert row.is_first_party is True
        assert row.is_trusted is False
        assert row.access_token_ttl_seconds == 3600
        assert row.refresh_token_ttl_seconds == 1209600


class TestRedirectURIValidation:
    def test_rejects_relative_uri(self) -> None:
        with pytest.raises(oidc_admin.OIDCValidationError, match="absolute"):
            oidc_admin._validate_redirect_uris(["/callback"])

    def test_rejects_fragment(self) -> None:
        with pytest.raises(oidc_admin.OIDCValidationError, match="fragment"):
            oidc_admin._validate_redirect_uris(["https://app.example.com/cb#frag"])

    def test_rejects_wildcard_or_whitespace(self) -> None:
        with pytest.raises(oidc_admin.OIDCValidationError, match="forbidden"):
            oidc_admin._validate_redirect_uris(["https://app.example.com/cb*"])
        with pytest.raises(oidc_admin.OIDCValidationError, match="forbidden"):
            oidc_admin._validate_redirect_uris(["https://app.example.com/cb extra"])

    def test_rejects_empty_list(self) -> None:
        with pytest.raises(oidc_admin.OIDCValidationError, match="At least one"):
            oidc_admin._validate_redirect_uris([])

    def test_accepts_valid_https_uri(self) -> None:
        oidc_admin._validate_redirect_uris(["https://app.example.com/callback"])


class TestRegistryValidation:
    def test_unsupported_grant_type_refused(self) -> None:
        with pytest.raises(oidc_admin.OIDCValidationError, match="grant_types"):
            oidc_admin._validate_collection_field(["password"], oidc_admin.SUPPORTED_GRANT_TYPES, "grant_types")

    def test_unsupported_scope_refused(self) -> None:
        with pytest.raises(oidc_admin.OIDCValidationError, match="scopes"):
            oidc_admin._validate_collection_field(["email"], oidc_admin.SUPPORTED_SCOPES, "scopes")


class TestCreateClientValidation:
    async def test_public_client_with_client_credentials_refused(self) -> None:
        with patch.object(oidc_admin, "oidc_repo"), patch.object(oidc_admin, "AuditLogger") as audit:
            with pytest.raises(oidc_admin.OIDCValidationError, match="client_credentials"):
                await oidc_admin.create_client(
                    MagicMock(),
                    _sample_create(grant_types=["client_credentials"]),
                )
            audit.return_value.log_event.assert_not_called()

    async def test_empty_secret_refused(self) -> None:
        with pytest.raises(oidc_admin.OIDCValidationError, match="non-empty"):
            await oidc_admin._hash_client_secret("")

    async def test_bad_client_id_format_refused(self) -> None:
        with pytest.raises(oidc_admin.OIDCValidationError, match="client_id"):
            await oidc_admin.create_client(MagicMock(), _sample_create(client_id="bad id!"))

    async def test_non_positive_ttl_refused(self) -> None:
        with pytest.raises(oidc_admin.OIDCValidationError, match="positive"):
            await oidc_admin.create_client(MagicMock(), _sample_create(access_token_ttl_seconds=0))


class TestCreateClientService:
    async def test_confidential_client_hash_secret_and_audits(self) -> None:
        session = MagicMock()
        with (
            patch.object(oidc_admin, "oidc_repo") as repo,
            patch.object(oidc_admin, "AuditLogger") as audit_logger,
        ):
            repo.create_client = AsyncMock(return_value=_client_row())
            audit_logger.return_value.log_event = AsyncMock()

            public = await oidc_admin.create_client(session, _sample_create(client_secret="s3cret"), actor_id="admin-1")

            stored = repo.create_client.call_args[0][1]
            assert stored["client_secret_hash"].startswith("$2b$")
            assert re.fullmatch(r"[0-9a-f]{32}", str(stored["client_id"])) is not None
            assert public.has_client_secret is True
            audit_logger.return_value.log_event.assert_awaited_once()
            assert audit_logger.return_value.log_event.call_args.kwargs["action"] == AuditAction.AUTH_OAUTH_CLIENT_CREATED

    async def test_generated_client_id_is_32_hex(self) -> None:
        with (
            patch.object(oidc_admin, "oidc_repo") as repo,
            patch.object(oidc_admin, "AuditLogger") as audit_logger,
        ):
            repo.create_client = AsyncMock(return_value=_client_row(client_id=uuid.uuid4().hex))
            audit_logger.return_value.log_event = AsyncMock()

            await oidc_admin.create_client(MagicMock(), _sample_create())

            stored = repo.create_client.call_args[0][1]
            assert re.fullmatch(r"[0-9a-f]{32}", stored["client_id"]) is not None

    async def test_public_client_has_no_hash(self) -> None:
        with (
            patch.object(oidc_admin, "oidc_repo") as repo,
            patch.object(oidc_admin, "AuditLogger") as audit_logger,
        ):
            repo.create_client = AsyncMock(return_value=_client_row(client_secret_hash=None))
            audit_logger.return_value.log_event = AsyncMock()

            public = await oidc_admin.create_client(MagicMock(), _sample_create())

            assert repo.create_client.call_args[0][1]["client_secret_hash"] is None
            assert public.has_client_secret is False


class TestUpdateClientService:
    async def test_missing_client_raises_value_error(self) -> None:
        with patch.object(oidc_admin, "oidc_repo") as repo:
            repo.get_client_by_id = AsyncMock(return_value=None)
            with pytest.raises(ValueError, match="not found"):
                await oidc_admin.update_client(MagicMock(), uuid.uuid4(), OIDCClientUpdate())

    async def test_secret_rotation_rehashes(self) -> None:
        row = _client_row()
        with (
            patch.object(oidc_admin, "oidc_repo") as repo,
            patch.object(oidc_admin, "AuditLogger") as audit_logger,
        ):
            repo.get_client_by_id = AsyncMock(return_value=row)
            repo.update_client = AsyncMock(return_value=row)
            audit_logger.return_value.log_event = AsyncMock()

            await oidc_admin.update_client(
                MagicMock(), uuid.uuid4(), OIDCClientUpdate(client_secret="newsecret"), actor_id="admin-1"
            )

            updates = repo.update_client.call_args[0][2]
            assert updates["client_secret_hash"].startswith("$2b$")
            assert updates["client_secret_hash"] != "$2b$12$abc"

    async def test_validation_error_is_distinguised_for_http_mapping(self) -> None:
        with patch.object(oidc_admin, "oidc_repo") as repo:
            repo.get_client_by_id = AsyncMock(return_value=_client_row())
            with pytest.raises(oidc_admin.OIDCValidationError):
                await oidc_admin.update_client(
                    MagicMock(), uuid.uuid4(), OIDCClientUpdate(redirect_uris=["/relative"])
                )


class TestDeleteClientService:
    async def test_cascades_and_audits(self) -> None:
        row = _client_row()
        with (
            patch.object(oidc_admin, "oidc_repo") as repo,
            patch.object(oidc_admin, "AuditLogger") as audit_logger,
        ):
            repo.get_client_by_id = AsyncMock(return_value=row)
            repo.delete_client_cascade = AsyncMock(return_value={"grant_codes": 1, "consents": 2, "refresh_tokens_revoked": 3})
            audit_logger.return_value.log_event = AsyncMock()

            counts = await oidc_admin.delete_client(MagicMock(), uuid.uuid4(), actor_id="admin-1")

            assert counts["refresh_tokens_revoked"] == 3
            assert audit_logger.return_value.log_event.call_args.kwargs["action"] == AuditAction.AUTH_OAUTH_CLIENT_DELETED

    async def test_missing_client_raises_value_error(self) -> None:
        with patch.object(oidc_admin, "oidc_repo") as repo:
            repo.get_client_by_id = AsyncMock(return_value=None)
            with pytest.raises(ValueError):
                await oidc_admin.delete_client(MagicMock(), uuid.uuid4())


class TestAuditActionSurface:
    def test_oidc_actions_registered(self) -> None:
        expected = [
            "auth.oauth_client_created",
            "auth.oauth_client_updated",
            "auth.oauth_client_deleted",
            "auth.consent_granted",
            "auth.consent_revoked",
            "auth.token_issued",
            "auth.token_revoked",
            "auth.token_family_revoked",
            "auth.oauth_key_rotated",
        ]
        registered = {action.value for action in AuditAction}
        assert set(expected) <= registered


class TestAdminRouterSurface:
    def test_router_mounts_five_client_routes(self) -> None:
        assert admin_oidc_router.prefix == "/admin/oidc"
        paths = [getattr(route, "path", "") for route in admin_oidc_router.routes]
        assert paths.count("/admin/oidc/clients") == 2
        assert paths.count("/admin/oidc/clients/{client_row_id}") == 3