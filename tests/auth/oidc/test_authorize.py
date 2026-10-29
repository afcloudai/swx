# pyright: reportAny=false, reportExplicitAny=false, reportUnknownMemberType=false, reportUnknownArgumentType=false, reportMissingImports=false, reportUnusedCallResult=false

"""
Unit tests for SWX-IDM-001 D-3a: /oidc/authorize validation matrix (fail-closed, audited).
"""

import uuid
from unittest.mock import AsyncMock, MagicMock, patch
from urllib.parse import parse_qs, urlsplit

import pytest
from fastapi.responses import RedirectResponse

from swx_core.auth.oidc_provider import grant_service as gv
from swx_core.auth.oidc_provider import repositories as oidc_repo
from swx_core.auth.oidc_provider import security as oidc_security
from swx_core.auth.oidc_provider.grant_service import OIDCAuthzError
from swx_core.auth.oidc_provider.models import OIDCClient
from swx_core.config.settings import settings
from swx_core.services.audit_logger import AuditAction, AuditOutcome

pytestmark = pytest.mark.unit

CLIENT_ID = "aabbccddeeff00112233445566778899"
REDIRECT_URI = "https://app.example.com/callback"


def client_row(**overrides: object) -> OIDCClient:
    data: dict[str, object] = {
        "name": "RP Client",
        "client_id": CLIENT_ID,
        "redirect_uris": [REDIRECT_URI],
        "grant_types": ["authorization_code", "refresh_token"],
        "scopes": ["openid", "profile", "phone"],
        "is_trusted": True,
    }
    data.update(overrides)
    return OIDCClient(**data)


def _audit_mock() -> MagicMock:
    mock = MagicMock()
    mock.log_event = AsyncMock()
    return mock


def _request(url: str = "https://idp.example.com/api/oidc/authorize?client_id=x") -> MagicMock:
    request = MagicMock()
    request.headers = {}
    request.cookies = {}
    request.query_params = {}
    request.session = {}
    request.url = url
    request.base_url = "https://idp.example.com/"
    return request


def valid_params(**overrides: str) -> dict[str, str]:
    params: dict[str, str] = {
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "response_type": "code",
        "scope": "openid profile phone",
        "state": "xyz",
        "code_challenge": oidc_security.s256_challenge("v" * 45),
        "code_challenge_method": "S256",
        "nonce": "n-123",
    }
    params.update(overrides)
    return params


def _redirect_fields(response: RedirectResponse) -> dict[str, str]:
    location = str(response.headers["location"])
    return {key: values[0] for key, values in parse_qs(urlsplit(location).query).items()}


class TestAuthorizeFailClosed:
    async def test_unknown_client_refused_without_redirect_and_audited(self) -> None:
        request = _request()
        with (
            patch.object(oidc_repo, "get_client_by_public_id", AsyncMock(return_value=None)),
            patch.object(gv, "AuditLogger") as audit_logger,
        ):
            audit_logger.return_value.log_event = AsyncMock()
            with pytest.raises(OIDCAuthzError, match="Unknown or disabled client"):
                await gv.authorize(MagicMock(), request, valid_params())

        audit_log = audit_logger.return_value.log_event.await_args
        assert audit_log is not None
        assert audit_log.kwargs["action"] == AuditAction.AUTH_OIDC_AUTHORIZE_DENIED
        assert audit_log.kwargs["outcome"] == AuditOutcome.FAILURE

    async def test_disabled_client_refused(self) -> None:
        request = _request()
        with (
            patch.object(oidc_repo, "get_client_by_public_id", AsyncMock(return_value=client_row(enabled=False))),
            patch.object(gv, "AuditLogger", return_value=_audit_mock()),
        ):
            with pytest.raises(OIDCAuthzError, match="Unknown or disabled client"):
                await gv.authorize(MagicMock(), request, valid_params())

    async def test_unregistered_redirect_never_redirected_to(self) -> None:
        request = _request()
        with (
            patch.object(oidc_repo, "get_client_by_public_id", AsyncMock(return_value=client_row())),
            patch.object(gv, "AuditLogger", return_value=_audit_mock()),
        ):
            tampered = "https://app.example.com/callback/extra"  # prefix, not exact
            with pytest.raises(OIDCAuthzError, match="not registered"):
                await gv.authorize(MagicMock(), request, valid_params(redirect_uri=tampered))


class TestAuthorizeErrorRedirects:
    async def test_unsupported_response_type(self) -> None:
        request = _request()
        with (
            patch.object(oidc_repo, "get_client_by_public_id", AsyncMock(return_value=client_row())),
            patch.object(gv, "AuditLogger", return_value=_audit_mock()),
        ):
            response = await gv.authorize(MagicMock(), request, valid_params(response_type="id_token"))
        fields = _redirect_fields(response)
        assert fields["error"] == "unsupported_response_type"
        assert fields["state"] == "xyz"
        assert response.status_code == 303

    async def test_grant_not_allowed(self) -> None:
        request = _request()
        restricted = client_row(grant_types=["refresh_token"])
        with (
            patch.object(oidc_repo, "get_client_by_public_id", AsyncMock(return_value=restricted)),
            patch.object(gv, "AuditLogger", return_value=_audit_mock()),
        ):
            response = await gv.authorize(MagicMock(), request, valid_params())
        assert _redirect_fields(response)["error"] == "unauthorized_client"

    async def test_scope_escalation(self) -> None:
        request = _request()
        with (
            patch.object(oidc_repo, "get_client_by_public_id", AsyncMock(return_value=client_row())),
            patch.object(gv, "AuditLogger", return_value=_audit_mock()),
        ):
            response = await gv.authorize(MagicMock(), request, valid_params(scope="openid email"))
        assert _redirect_fields(response)["error"] == "invalid_scope"

    async def test_public_client_without_pkce(self) -> None:
        request = _request()
        with (
            patch.object(oidc_repo, "get_client_by_public_id", AsyncMock(return_value=client_row())),
            patch.object(gv, "AuditLogger", return_value=_audit_mock()),
        ):
            response = await gv.authorize(
                MagicMock(), request, {k: v for k, v in valid_params().items() if not k.startswith("code_")}
            )
        assert _redirect_fields(response)["error"] == "invalid_request"

    async def test_pkce_downgrade_plain_refused(self) -> None:
        request = _request()
        with (
            patch.object(oidc_repo, "get_client_by_public_id", AsyncMock(return_value=client_row())),
            patch.object(gv, "AuditLogger", return_value=_audit_mock()),
        ):
            response = await gv.authorize(MagicMock(), request, valid_params(code_challenge_method="plain"))
        assert _redirect_fields(response)["error"] == "invalid_request"


class TestAuthorizeHappyPaths:
    async def test_anonymous_user_gets_login_redirect_with_pending_grant(self) -> None:
        request = _request()
        with (
            patch.object(oidc_repo, "get_client_by_public_id", AsyncMock(return_value=client_row())),
            patch.object(gv, "_resolve_optional_user", AsyncMock(return_value=(None, None))),
            patch.object(gv, "AuditLogger", return_value=_audit_mock()),
        ):
            response = await gv.authorize(MagicMock(), request, valid_params())

        location = str(response.headers["location"])
        assert location.startswith(settings.SWX_OIDC_LOGIN_URL)
        assert "next=" in location
        assert request.session["oidc_pending_grant"]["client_id"] == CLIENT_ID
        assert request.session["oidc_pending_grant"]["nonce"] == "n-123"

    async def test_authenticated_user_issues_code_and_consent(self) -> None:
        request = _request()
        session = MagicMock()
        user = MagicMock(id=uuid.uuid4())
        with (
            patch.object(oidc_repo, "get_client_by_public_id", AsyncMock(return_value=client_row())),
            patch.object(gv, "_resolve_optional_user", AsyncMock(return_value=(user, {"iat": 1760000000.0}))),
            patch.object(oidc_repo, "create_grant_code", AsyncMock(return_value=MagicMock())) as create_code,
            patch.object(oidc_repo, "upsert_consent", AsyncMock(return_value=MagicMock())) as upsert,
            patch.object(gv, "AuditLogger") as audit_logger,
        ):
            audit_logger.return_value.log_event = AsyncMock()

            response = await gv.authorize(session, request, valid_params())

        stored = create_code.await_args.args[1]
        assert len(stored["code_hash"]) == 64
        assert stored["client_id"] == CLIENT_ID
        assert stored["nonce"] == "n-123"
        assert stored["acr"] == "urn:swx:acr:pwd"
        assert stored["amr"] == ["pwd"]
        assert stored["auth_time"] is not None
        upsert.assert_awaited_once_with(session, user_id=user.id, client_id=CLIENT_ID, scope="openid profile phone")

        fields = _redirect_fields(response)
        assert fields["state"] == "xyz"
        assert len(fields["code"]) > 20
        assert "oidc_pending_grant" not in request.session

        actions = [call.kwargs["action"] for call in audit_logger.return_value.log_event.await_args_list]
        assert AuditAction.AUTH_CONSENT_GRANTED in actions

    async def test_confidential_client_without_pkce_refused(self) -> None:
        """OAuth 2.1: PKCE is mandatory for ALL clients (test-codified deviation from L-8)."""
        request = _request()
        confidential = client_row(client_secret_hash="$2b$12$dummy")
        audit = _audit_mock()
        params = {k: v for k, v in valid_params().items() if not k.startswith("code_")}
        with (
            patch.object(oidc_repo, "get_client_by_public_id", AsyncMock(return_value=confidential)),
            patch.object(gv, "_resolve_optional_user", AsyncMock(return_value=(MagicMock(id=uuid.uuid4()), {"iat": 1760000000.0}))),
            patch.object(oidc_repo, "create_grant_code", AsyncMock(return_value=MagicMock())) as create_code,
            patch.object(oidc_repo, "upsert_consent", AsyncMock(return_value=MagicMock())),
            patch.object(gv, "AuditLogger", return_value=audit),
        ):
            response = await gv.authorize(MagicMock(), request, params)

        fields = _redirect_fields(response)
        assert fields["error"] == "invalid_request" and fields["error_description"].startswith("PKCE")
        create_code.assert_not_awaited()
        assert audit.log_event.await_args.kwargs["action"] == AuditAction.AUTH_OIDC_AUTHORIZE_DENIED
        assert audit.log_event.await_args.kwargs["context"]["reason"] == "pkce_missing_or_downgraded"

    async def test_nonce_not_required_but_honored(self) -> None:
        """OIDC Core: nonce is optional in the code flow — honored (stored) when present."""
        request = _request()
        with (
            patch.object(oidc_repo, "get_client_by_public_id", AsyncMock(return_value=client_row())),
            patch.object(gv, "_resolve_optional_user", AsyncMock(return_value=(MagicMock(id=uuid.uuid4()), {"iat": 1760000000.0}))),
            patch.object(oidc_repo, "create_grant_code", AsyncMock(return_value=MagicMock())) as create_code,
            patch.object(oidc_repo, "upsert_consent", AsyncMock(return_value=MagicMock())),
            patch.object(gv, "AuditLogger", return_value=_audit_mock()),
        ):
            response = await gv.authorize(MagicMock(), request, valid_params())  # nonce present

        stored = create_code.await_args.args[1]
        assert stored["nonce"] == "n-123"

    async def test_nonce_absent_still_issues(self) -> None:
        request = _request()
        with (
            patch.object(oidc_repo, "get_client_by_public_id", AsyncMock(return_value=client_row())),
            patch.object(gv, "_resolve_optional_user", AsyncMock(return_value=(MagicMock(id=uuid.uuid4()), {"iat": 1760000000.0}))),
            patch.object(oidc_repo, "create_grant_code", AsyncMock(return_value=MagicMock())) as create_code,
            patch.object(oidc_repo, "upsert_consent", AsyncMock(return_value=MagicMock())),
            patch.object(gv, "AuditLogger", return_value=_audit_mock()),
        ):
            response = await gv.authorize(MagicMock(), request, valid_params(nonce=""))

        assert _redirect_fields(response)["code"]
        assert create_code.await_args.args[1]["nonce"] is None