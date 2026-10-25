# pyright: reportAny=false, reportExplicitAny=false, reportUnknownMemberType=false, reportUnknownArgumentType=false, reportMissingImports=false, reportUnusedCallResult=false, reportAttributeAccessIssue=false, reportArgumentType=false, reportCallIssue=false

"""
Conformance tests for introspection (RFC 7662), RP-initiated logout
(end_session_endpoint / OIDC Session Management) — v2.31 gap closure.
"""

import uuid
from datetime import timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from swx_core.auth.oidc_provider import grant_service as gv
from swx_core.auth.oidc_provider import keys as oidc_keys
from swx_core.auth.oidc_provider import repositories as oidc_repo
from swx_core.auth.oidc_provider import security as oidc_security
from swx_core.auth.oidc_provider import tokens as oidc_tokens
from swx_core.auth.oidc_provider.grant_service import OIDCAuthzError
from swx_core.auth.oidc_provider.models import OIDCClient, OIDCSigningKey
from swx_core.security import encryption as encryption_module
from swx_core.utils.time import utc_now

pytestmark = pytest.mark.unit

CLIENT_ID = "aabbccddeeff00112233445566778899"
OTHER_CLIENT_ID = "ffffffffffffffffffffffffffffffff"
USER_ID = uuid.uuid4()
ISSUER = "https://idp.example.com/api"
URI = "https://app.example.com/logout"


def _key_row_for_pem(kid: str, pem: str, jwk: dict) -> OIDCSigningKey:
    return OIDCSigningKey(kid=kid, algorithm="RS256", private_key_encrypted=pem, public_jwk=jwk, status="active")


def _minting_patches():  # type: ignore[no-untyped-def]
    kid, pem, jwk = oidc_keys.generate_keypair("RS256")
    row = _key_row_for_pem(kid, pem, jwk)
    return (
        patch.object(encryption_module, "decrypt_value", new=lambda value: value),
        patch.object(oidc_repo, "get_active_signing_key", AsyncMock(return_value=row)),
        patch.object(oidc_repo, "get_signing_key_by_kid", AsyncMock(return_value=row)),
        patch.object(oidc_repo, "revoke_families_for_user", AsyncMock(return_value=3)),
    )


def _audit_mock() -> MagicMock:
    mock = MagicMock()
    mock.log_event = AsyncMock()
    return mock


def _request_with_token(token: str | None) -> MagicMock:
    request = MagicMock()
    request.headers = {"Authorization": f"Bearer {token}"} if token else {}
    request.cookies = {}
    request.query_params = {}
    request.session = {}
    request.base_url = "https://idp.example.com/"
    return request


def confidential() -> OIDCClient:
    return OIDCClient(
        name="RP",
        client_id=CLIENT_ID,
        client_secret_hash="$2b$12$dummy",
        post_logout_redirect_uris=[URI],
    )


class TestIntrospection:
    async def test_active_access_token_introspects_with_claims(self) -> None:
        patches = _minting_patches()
        audit = _audit_mock()
        blacklist = MagicMock()
        blacklist.is_revoked_by_jti = AsyncMock(return_value=False)
        with (
            patches[0], patches[1], patches[2],
            patch.object(oidc_security, "authenticate_client", AsyncMock(return_value=confidential())),
            patch.object(gv, "_get_token_blacklist", return_value=blacklist),
            patch.object(gv, "AuditLogger", return_value=audit),
        ):
            access = await oidc_tokens.mint_access_token(
                MagicMock(), issuer=ISSUER, subject=str(USER_ID), client_id=CLIENT_ID,
                scope="openid", expires_delta=timedelta(minutes=10),
            )
            result = await gv.introspect(MagicMock(), _request_with_token(None), {"token": access})

        assert result["active"] is True
        assert result["sub"] == str(USER_ID)
        assert result["client_id"] == CLIENT_ID
        assert result["scope"] == "openid"
        assert result["exp"] and result["jti"]

    async def test_cross_client_token_is_inactive_and_audited(self) -> None:
        patches = _minting_patches()
        audit = _audit_mock()
        blacklist = MagicMock()
        blacklist.is_revoked_by_jti = AsyncMock(return_value=False)
        with (
            patches[0], patches[1], patches[2],
            patch.object(oidc_security, "authenticate_client", AsyncMock(return_value=confidential())),
            patch.object(gv, "_get_token_blacklist", return_value=blacklist),
            patch.object(gv, "AuditLogger", return_value=audit),
        ):
            other_access = await oidc_tokens.mint_access_token(
                MagicMock(), issuer=ISSUER, subject=str(USER_ID), client_id=OTHER_CLIENT_ID,
                scope="openid", expires_delta=timedelta(minutes=10),
            )
            result = await gv.introspect(MagicMock(), _request_with_token(None), {"token": other_access})

        assert result == {"active": False}
        assert audit.log_event.await_args.kwargs["context"]["reason"] == "cross_client_token"

    async def test_blacklisted_token_is_inactive(self) -> None:
        patches = _minting_patches()
        blacklist = MagicMock()
        blacklist.is_revoked_by_jti = AsyncMock(return_value=True)
        with (
            patches[0], patches[1], patches[2],
            patch.object(oidc_security, "authenticate_client", AsyncMock(return_value=confidential())),
            patch.object(gv, "_get_token_blacklist", return_value=blacklist),
        ):
            access = await oidc_tokens.mint_access_token(
                MagicMock(), issuer=ISSUER, subject=str(USER_ID), client_id=CLIENT_ID,
                scope="openid", expires_delta=timedelta(minutes=10),
            )
            result = await gv.introspect(MagicMock(), _request_with_token(None), {"token": access})

        assert result == {"active": False}

    async def test_expired_token_is_inactive(self) -> None:
        patches = _minting_patches()
        with (
            patches[0], patches[1], patches[2],
            patch.object(oidc_security, "authenticate_client", AsyncMock(return_value=confidential())),
        ):
            expired = await oidc_tokens.mint_access_token(
                MagicMock(), issuer=ISSUER, subject=str(USER_ID), client_id=CLIENT_ID,
                scope="openid", expires_delta=timedelta(seconds=-10),
            )
            result = await gv.introspect(MagicMock(), _request_with_token(None), {"token": expired})

        assert result == {"active": False}

    async def test_active_refresh_token_introspects(self) -> None:
        patches = _minting_patches()
        row = MagicMock(client_id=CLIENT_ID, user_id=USER_ID, scope="openid offline_access", status="active",
                        expires_at=utc_now() + timedelta(seconds=999))
        with (
            patches[0],
            patch.object(oidc_security, "authenticate_client", AsyncMock(return_value=confidential())),
            patch.object(oidc_repo, "get_refresh_token_by_hash", AsyncMock(return_value=row)),
        ):
            result = await gv.introspect(MagicMock(), _request_with_token(None), {"token": "refresh-value"})

        assert result["active"] is True and result["scope"] == "openid offline_access"

    async def test_rotated_refresh_token_introspects_inactive(self) -> None:
        patches = _minting_patches()
        row = MagicMock(client_id=CLIENT_ID, user_id=USER_ID, status="rotated",
                        expires_at=utc_now() + timedelta(seconds=999))
        with (
            patches[0],
            patch.object(oidc_security, "authenticate_client", AsyncMock(return_value=confidential())),
            patch.object(oidc_repo, "get_refresh_token_by_hash", AsyncMock(return_value=row)),
        ):
            result = await gv.introspect(MagicMock(), _request_with_token(None), {"token": "rotated-value"})

        assert result == {"active": False}

    async def test_public_client_refused(self) -> None:
        public_client = OIDCClient(name="SPA", client_id=CLIENT_ID)
        patches = _minting_patches()
        audit = _audit_mock()
        with (
            patches[0],
            patch.object(oidc_security, "authenticate_client", AsyncMock(return_value=public_client)),
            patch.object(gv, "AuditLogger", return_value=audit),
        ):
            with pytest.raises(OIDCAuthzError, match="confidential"):
                await gv.introspect(MagicMock(), _request_with_token(None), {"token": "x"})

    async def test_missing_token_is_invalid_request(self) -> None:
        patches = _minting_patches()
        with (
            patches[0],
            patch.object(oidc_security, "authenticate_client", AsyncMock(return_value=confidential())),
        ):
            with pytest.raises(OIDCAuthzError, match="token is required"):
                await gv.introspect(MagicMock(), _request_with_token(None), {})


class TestEndSession:
    def _hint(self, session: MagicMock):  # type: ignore[no-untyped-def]
        from cryptography.hazmat.primitives import serialization

        patches = _minting_patches()
        with patches[0], patches[1]:
            _ = serialization
            hint = None
        return hint, patches

    async def test_full_logout_revokes_and_redirects(self) -> None:
        patches = _minting_patches()
        audit = _audit_mock()
        session = MagicMock()
        user = MagicMock(id=USER_ID, email="ayo@example.com")
        session.get = AsyncMock(return_value=user)
        session.pop = MagicMock()

        with patches[0], patches[1]:
            hint = await oidc_tokens.mint_id_token(
                MagicMock(), issuer=ISSUER, subject=str(USER_ID), client_id=CLIENT_ID,
                expires_delta=timedelta(minutes=10),
            )

        families_mock = AsyncMock(return_value=3)
        with (
            patches[0], patches[2],
            patch.object(oidc_repo, "revoke_families_for_user", new=families_mock),
            patch.object(oidc_repo, "get_client_by_public_id", AsyncMock(return_value=confidential())),
            patch("swx_core.security.refresh_token_service.revoke_all_tokens", AsyncMock()) as revoke_platform,
            patch.object(gv, "AuditLogger", return_value=audit),
        ):
            response = await gv.end_session(
                session, _request_with_token(None),
                {"id_token_hint": hint, "post_logout_redirect_uri": URI, "state": "bye"},
            )

        assert response.status_code == 303
        assert str(response.headers["location"]) == URI
        revoke_platform.assert_awaited_once()
        revoke_args = families_mock.await_args
        assert revoke_args is not None
        assert revoke_args.args[1] == USER_ID
        assert str(response.headers["location"]) == URI
        actions = [call.kwargs["action"] for call in audit.log_event.await_args_list]
        assert "auth.logout" in actions and "auth.token_revoked" in actions

    async def test_invalid_hint_never_revokes(self) -> None:
        patches = _minting_patches()
        audit = _audit_mock()
        with (
            patches[0], patches[2],
            patch.object(gv, "AuditLogger", return_value=audit),
        ):
            with pytest.raises(OIDCAuthzError, match="Invalid id_token_hint"):
                await gv.end_session(MagicMock(), _request_with_token(None), {"id_token_hint": "garbage.token.value"})

        assert audit.log_event.await_args.kwargs["outcome"].value == "failure"

    async def test_unregistered_post_logout_uri_refused(self) -> None:
        patches = _minting_patches()
        with patches[0], patches[1]:
            hint = await oidc_tokens.mint_id_token(
                MagicMock(), issuer=ISSUER, subject=str(USER_ID), client_id=CLIENT_ID,
                expires_delta=timedelta(minutes=10),
            )
        with (
            patches[0], patches[2],
            patch.object(oidc_repo, "get_client_by_public_id", AsyncMock(return_value=confidential())),
            patch.object(gv, "AuditLogger", return_value=_audit_mock()),
        ):
            with pytest.raises(OIDCAuthzError, match="not registered"):
                await gv.end_session(MagicMock(), _request_with_token(None),
                                     {"id_token_hint": hint, "post_logout_redirect_uri": "https://evil.example.com/x"})

    async def test_no_hint_clears_session_json(self) -> None:
        session = MagicMock()
        session.pop = MagicMock()
        session_state = {"oidc_pending_grant": {"x": 1}}
        session.pop = MagicMock(side_effect=lambda *a, **k: session_state.pop(*a, **k))
        request = _request_with_token(None)
        request.session = session_state

        result = await gv.end_session(MagicMock(), request, {})

        assert result.status_code == 200
        assert session_state == {}

    async def test_discovery_advertises_end_session(self) -> None:
        from swx_core.auth.oidc_provider.grant_service import derive_issuer, issuer_endpoint_urls

        issuer = derive_issuer(_request_with_token(None))
        urls = issuer_endpoint_urls(issuer)
        assert urls["end_session"].endswith("/oidc/logout")