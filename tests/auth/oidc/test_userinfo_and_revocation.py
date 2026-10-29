# pyright: reportAny=false, reportExplicitAny=false, reportUnknownMemberType=false, reportUnknownArgumentType=false, reportMissingImports=false, reportUnusedCallResult=false, reportAttributeAccessIssue=false, reportArgumentType=false, reportCallIssue=false

"""
Unit tests for SWX-IDM-001 D-3c: /oidc/userinfo claims + /oidc/revoke (RFC 7009).
"""

import uuid
from typing import Any
from datetime import timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import jwt as pyjwt
import pytest
from cryptography.hazmat.primitives import serialization

from swx_core.auth.oidc_provider import grant_service as gv
from swx_core.auth.oidc_provider import keys as oidc_keys
from swx_core.auth.oidc_provider import repositories as oidc_repo
from swx_core.auth.oidc_provider import security as oidc_security
from swx_core.auth.oidc_provider import tokens as oidc_tokens
from swx_core.auth.oidc_provider.grant_service import OIDCAuthzError
from swx_core.auth.oidc_provider.models import OIDCClient, OIDCSigningKey
from swx_core.security import encryption as encryption_module
from swx_core.services.audit_logger import AuditAction, AuditOutcome
from swx_core.utils.time import utc_now

pytestmark = pytest.mark.unit

CLIENT_ID = "aabbccddeeff00112233445566778899"
OTHER_CLIENT_ID = "ffffffffffffffffffffffffffffffff"
USER_ID = uuid.uuid4()
FAMILY_ID = uuid.uuid4()
ISSUER = "https://idp.example.com/api"


def client_row(**overrides: object) -> OIDCClient:
    data: dict[str, object] = {
        "name": "RP Client",
        "client_id": CLIENT_ID,
        "redirect_uris": ["https://app.example.com/callback"],
        "grant_types": ["authorization_code", "refresh_token", "client_credentials"],
        "scopes": ["openid", "profile", "phone"],
        "is_trusted": True,
    }
    data.update(overrides)
    return OIDCClient(**data)


def _key_harness() -> tuple[OIDCSigningKey, object]:
    kid, pem, jwk = oidc_keys.generate_keypair("RS256")
    row = OIDCSigningKey(kid=kid, algorithm="RS256", private_key_encrypted=pem, public_jwk=jwk, status="active")
    public_key = serialization.load_pem_private_key(pem.encode(), password=None).public_key()
    return row, public_key


def _minting_patches(key_row: OIDCSigningKey) -> tuple[Any, ...]:
    return (
        patch.object(encryption_module, "decrypt_value", new=lambda value: value),
        patch.object(oidc_repo, "get_active_signing_key", AsyncMock(return_value=key_row)),
        patch.object(oidc_repo, "get_signing_key_by_kid", AsyncMock(return_value=key_row)),
    )


def _user(**overrides: object) -> MagicMock:
    user = MagicMock(id=USER_ID, is_active=True, full_name="Ayo Ade", phone="+2348012345678", phone_verified_at=utc_now())
    for key, value in overrides.items():
        setattr(user, key, value)
    return user


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


class TestUserinfo:
    async def test_scope_gated_claims_with_verified_phone(self) -> None:
        key_row, _ = _key_harness()
        session = MagicMock()
        session.get = AsyncMock(return_value=_user())
        patches = _minting_patches(key_row)
        with (
            patches[0],
            patches[1],
            patches[2],
            patch.object(oidc_repo, "get_client_by_public_id", AsyncMock(return_value=client_row())),
        ):
            access = await oidc_tokens.mint_access_token(
                MagicMock(), issuer=ISSUER, subject=str(USER_ID), client_id=CLIENT_ID,
                scope="openid profile phone", expires_delta=timedelta(minutes=10),
            )
            claims = await gv.userinfo(session, _request_with_token(access))

        assert claims["sub"] == str(USER_ID)
        assert claims["name"] == "Ayo Ade"
        assert claims["phone"] == "+2348012345678"
        assert claims["phone_verified"] is True

    async def test_unverified_phone_reports_false(self) -> None:
        key_row, _ = _key_harness()
        session = MagicMock()
        session.get = AsyncMock(return_value=_user(phone_verified_at=None))
        patches = _minting_patches(key_row)
        with (
            patches[0],
            patches[1],
            patches[2],
            patch.object(oidc_repo, "get_client_by_public_id", AsyncMock(return_value=client_row())),
        ):
            access = await oidc_tokens.mint_access_token(
                MagicMock(), issuer=ISSUER, subject=str(USER_ID), client_id=CLIENT_ID,
                scope="openid profile phone", expires_delta=timedelta(minutes=10),
            )
            claims = await gv.userinfo(session, _request_with_token(access))

        assert claims["phone"] == "+2348012345678"
        assert claims["phone_verified"] is False

    async def test_phone_claims_omitted_without_phone_scope(self) -> None:
        key_row, _ = _key_harness()
        session = MagicMock()
        session.get = AsyncMock(return_value=_user())
        patches = _minting_patches(key_row)
        with (
            patches[0],
            patches[1],
            patches[2],
            patch.object(oidc_repo, "get_client_by_public_id", AsyncMock(return_value=client_row())),
        ):
            access = await oidc_tokens.mint_access_token(
                MagicMock(), issuer=ISSUER, subject=str(USER_ID), client_id=CLIENT_ID,
                scope="openid profile", expires_delta=timedelta(minutes=10),
            )
            claims = await gv.userinfo(session, _request_with_token(access))

        assert claims["sub"] == str(USER_ID)
        assert "phone" not in claims
        assert "phone_verified" not in claims

    async def test_missing_bearer_header_refused(self) -> None:
        with pytest.raises(OIDCAuthzError) as exc_info:
            await gv.userinfo(MagicMock(), _request_with_token(None))
        assert exc_info.value.error == "invalid_token"
        assert exc_info.value.status_code == 401

    async def test_refusals_audited(self) -> None:
        audit = _audit_mock()
        with patch.object(gv, "AuditLogger", return_value=audit):
            with pytest.raises(OIDCAuthzError):
                await gv.userinfo(MagicMock(), _request_with_token("garbage.token.value"))

        assert audit.log_event.await_args.kwargs["action"] == AuditAction.AUTH_OIDC_TOKEN_DENIED
        assert audit.log_event.await_args.kwargs["context"]["path"] == "userinfo"

    async def test_userinfo_401_carries_www_authenticate(self) -> None:
        """RFC 6750 §3: the bearer challenge header rides every userinfo 401."""
        from swx_core.auth.oidc_provider.routers import userinfo_endpoint

        response = await userinfo_endpoint(_request_with_token(None), MagicMock())

        assert response.status_code == 401
        assert response.headers["www-authenticate"] == 'Bearer error="invalid_token"'

    async def test_garbage_token_refused(self) -> None:
        key_row, _ = _key_harness()
        patches = _minting_patches(key_row)
        with patches[0], patches[1], patches[2]:
            with pytest.raises(OIDCAuthzError, match="invalid or expired"):
                await gv.userinfo(MagicMock(), _request_with_token("not.a.jwt"))

    async def test_platform_audience_token_refused(self) -> None:
        key_row, _ = _key_harness()
        forged = pyjwt.encode(
            {"sub": str(USER_ID), "aud": "user", "exp": (utc_now() + timedelta(minutes=5)).timestamp(), "client_id": CLIENT_ID},
            key_row.private_key_encrypted,
            algorithm="RS256",
            headers={"kid": key_row.kid},
        )
        patches = _minting_patches(key_row)
        with patches[0], patches[1], patches[2]:
            with pytest.raises(OIDCAuthzError, match="not an OIDC client"):
                await gv.userinfo(MagicMock(), _request_with_token(forged))

    async def test_unknown_audience_client_refused(self) -> None:
        key_row, _ = _key_harness()
        patches = _minting_patches(key_row)
        with (
            patches[0],
            patches[1],
            patches[2],
            patch.object(oidc_repo, "get_client_by_public_id", AsyncMock(return_value=None)),
            pytest.raises(OIDCAuthzError, match="not an active client"),
        ):
            access = await oidc_tokens.mint_access_token(
                MagicMock(), issuer=ISSUER, subject=str(USER_ID), client_id=CLIENT_ID,
                scope="openid", expires_delta=timedelta(minutes=10),
            )
            await gv.userinfo(MagicMock(), _request_with_token(access))

    async def test_inactive_user_refused(self) -> None:
        key_row, _ = _key_harness()
        session = MagicMock()
        session.get = AsyncMock(return_value=_user(is_active=False))
        patches = _minting_patches(key_row)
        with (
            patches[0],
            patches[1],
            patches[2],
            patch.object(oidc_repo, "get_client_by_public_id", AsyncMock(return_value=client_row())),
            pytest.raises(OIDCAuthzError, match="no longer active"),
        ):
            access = await oidc_tokens.mint_access_token(
                MagicMock(), issuer=ISSUER, subject=str(USER_ID), client_id=CLIENT_ID,
                scope="openid", expires_delta=timedelta(minutes=10),
            )
            await gv.userinfo(session, _request_with_token(access))


class TestRevocation:
    async def test_refresh_revoke_rolls_family(self) -> None:
        key_row, _ = _key_harness()
        confidential = client_row(client_secret_hash="$2b$12$dummy", is_first_party=True)
        row = MagicMock(client_id=CLIENT_ID, family_id=FAMILY_ID, user_id=USER_ID)
        session = MagicMock()
        patches = _minting_patches(key_row)
        with (
            patches[0],
            patches[1],
            patches[2],
            patch.object(oidc_security, "authenticate_client", AsyncMock(return_value=confidential)),
            patch.object(oidc_repo, "get_refresh_token_by_hash", AsyncMock(return_value=row)),
            patch.object(oidc_repo, "revoke_family", AsyncMock(return_value=2)) as revoke_family,
            patch.object(gv, "AuditLogger") as audit_logger,
        ):
            audit_logger.return_value.log_event = AsyncMock()
            result = await gv.revoke(session, _request_with_token(None), {"token": "some-refresh", "client_id": CLIENT_ID})

        assert result == {}
        revoke_family.assert_awaited_once_with(session, FAMILY_ID)

    async def test_cross_client_refresh_revoke_audited(self) -> None:
        key_row, _ = _key_harness()
        confidential = client_row(client_secret_hash="$2b$12$dummy", is_first_party=True)
        row = MagicMock(client_id=OTHER_CLIENT_ID, family_id=FAMILY_ID, user_id=USER_ID)
        audit = _audit_mock()
        patches = _minting_patches(key_row)
        with (
            patches[0],
            patches[1],
            patches[2],
            patch.object(oidc_security, "authenticate_client", AsyncMock(return_value=confidential)),
            patch.object(oidc_repo, "get_refresh_token_by_hash", AsyncMock(return_value=row)),
            patch.object(oidc_repo, "revoke_family", AsyncMock(return_value=0)) as revoke_family,
            patch.object(gv, "AuditLogger", return_value=audit),
        ):
            result = await gv.revoke(MagicMock(), _request_with_token(None), {"token": "stolen-refresh", "client_id": CLIENT_ID})

        assert result == {}
        revoke_family.assert_not_awaited()
        assert audit.log_event.await_args.kwargs["action"] == AuditAction.AUTH_OIDC_TOKEN_DENIED
        assert audit.log_event.await_args.kwargs["context"]["reason"] == "cross_client_revocation_attempt"

    async def test_cross_client_access_revoke_audited(self) -> None:
        key_row, _ = _key_harness()
        confidential = client_row(client_secret_hash="$2b$12$dummy", is_first_party=True)
        audit = _audit_mock()
        blacklist = MagicMock()
        blacklist.revoke = AsyncMock()
        patches = _minting_patches(key_row)
        with (
            patches[0],
            patches[1],
            patches[2],
            patch.object(oidc_security, "authenticate_client", AsyncMock(return_value=confidential)),
            patch.object(gv, "_get_token_blacklist", return_value=blacklist),
            patch.object(gv, "AuditLogger", return_value=audit),
        ):
            access = await oidc_tokens.mint_access_token(
                MagicMock(), issuer=ISSUER, subject=str(USER_ID), client_id=OTHER_CLIENT_ID,
                scope="openid", expires_delta=timedelta(minutes=10),
            )
            result = await gv.revoke(MagicMock(), _request_with_token(None), {"token": access, "client_id": CLIENT_ID})

        assert result == {}
        blacklist.revoke.assert_not_awaited()
        assert audit.log_event.await_args.kwargs["context"]["reason"] == "cross_client_token"

    async def test_access_token_revoke_blacklists_jti(self) -> None:
        key_row, public_key = _key_harness()
        confidential = client_row(client_secret_hash="$2b$12$dummy", is_first_party=True)
        blacklist = MagicMock(revoke=AsyncMock())
        patches = _minting_patches(key_row)
        with (
            patches[0],
            patches[1],
            patches[2],
            patch.object(oidc_security, "authenticate_client", AsyncMock(return_value=confidential)),
            patch.object(gv, "_get_token_blacklist", return_value=blacklist),
            patch.object(gv, "AuditLogger") as audit_logger,
        ):
            audit_logger.return_value.log_event = AsyncMock()
            access = await oidc_tokens.mint_access_token(
                MagicMock(), issuer=ISSUER, subject=str(USER_ID), client_id=CLIENT_ID,
                scope="openid", expires_delta=timedelta(minutes=10),
            )
            claims = pyjwt.decode(access, public_key, algorithms=["RS256"], audience=f"oidc_client:{CLIENT_ID}")
            result = await gv.revoke(MagicMock(), _request_with_token(None), {"token": access, "client_id": CLIENT_ID})

        assert result == {}
        revoked_jti, ttl = blacklist.revoke.await_args.args
        assert revoked_jti == claims["jti"]
        assert ttl >= 1

    async def test_unknown_refresh_token_yields_silent_noop(self) -> None:
        key_row, _ = _key_harness()
        confidential = client_row(client_secret_hash="$2b$12$dummy", is_first_party=True)
        patches = _minting_patches(key_row)
        with (
            patches[0],
            patches[1],
            patches[2],
            patch.object(oidc_security, "authenticate_client", AsyncMock(return_value=confidential)),
            patch.object(oidc_repo, "get_refresh_token_by_hash", AsyncMock(return_value=None)),
            patch.object(oidc_repo, "revoke_family", AsyncMock(return_value=0)) as revoke_family,
        ):
            result = await gv.revoke(MagicMock(), _request_with_token(None), {"token": "never-existed", "client_id": CLIENT_ID})

        assert result == {}
        revoke_family.assert_not_awaited()

    async def test_missing_token_param_is_invalid_request(self) -> None:
        key_row, _ = _key_harness()
        confidential = client_row(client_secret_hash="$2b$12$dummy", is_first_party=True)
        patches = _minting_patches(key_row)
        with patches[0], patches[1], patches[2], patch.object(oidc_security, "authenticate_client", AsyncMock(return_value=confidential)):
            with pytest.raises(OIDCAuthzError, match="token is required"):
                await gv.revoke(MagicMock(), _request_with_token(None), {"client_id": CLIENT_ID})