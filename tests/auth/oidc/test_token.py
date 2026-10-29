# pyright: reportAny=false, reportExplicitAny=false, reportUnknownMemberType=false, reportUnknownArgumentType=false, reportMissingImports=false, reportUnusedCallResult=false, reportArgumentType=false

"""
Unit tests for SWX-IDM-001 D-3b: /oidc/token grants, rotation + reuse detection.
Tokens are minted with a REAL RS256 key so kid/at_hash/audience claims are verified.
"""

import uuid
from typing import Any
from datetime import datetime, timedelta, timezone
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
from swx_core.services.audit_logger import AuditAction
from swx_core.utils.time import utc_now

pytestmark = pytest.mark.unit

CLIENT_ID = "aabbccddeeff00112233445566778899"
OTHER_CLIENT_ID = "ffffffffffffffffffffffffffffffff"
USER_ID = uuid.uuid4()
REFRESH_ID = uuid.uuid4()
FAMILY_ID = uuid.uuid4()
REDIRECT_URI = "https://app.example.com/callback"
AUTH_TIME = datetime.fromtimestamp(1760000000.0, tz=timezone.utc)
VERIFIER = "v" * 45


def client_row(**overrides: object) -> OIDCClient:
    data: dict[str, object] = {
        "name": "RP Client",
        "client_id": CLIENT_ID,
        "redirect_uris": [REDIRECT_URI],
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


def _request() -> MagicMock:
    request = MagicMock()
    request.headers = {}
    request.cookies = {}
    request.query_params = {}
    request.session = {}
    request.base_url = "https://idp.example.com/"
    return request


def _code_row(**overrides: object) -> MagicMock:
    row = MagicMock(
        id=uuid.uuid4(),
        client_id=CLIENT_ID,
        redirect_uri=REDIRECT_URI,
        scope="openid phone",
        code_challenge=oidc_security.s256_challenge(VERIFIER),
        code_challenge_method="S256",
        nonce="n-123",
        auth_time=AUTH_TIME,
        acr="urn:swx:acr:pwd",
        amr=["pwd"],
        expires_at=utc_now() + timedelta(seconds=60),
        user_id=USER_ID,
    )
    for key, value in overrides.items():
        setattr(row, key, value)
    return row


def _audit_mock() -> MagicMock:
    mock = MagicMock()
    mock.log_event = AsyncMock()
    return mock


def _grant_patches(key_row: OIDCSigningKey, client: OIDCClient) -> tuple[Any, ...]:
    return (
        patch.object(oidc_repo, "get_active_signing_key", AsyncMock(return_value=key_row)),
        patch.object(encryption_module, "decrypt_value", new=lambda value: value),
        patch.object(oidc_security, "authenticate_client", AsyncMock(return_value=client)),
        patch.object(gv, "AuditLogger", return_value=_audit_mock()),
    )


AUDIENCE = f"oidc_client:{CLIENT_ID}"


def _decode(token: str, public_key: object, audience: str) -> dict:
    return pyjwt.decode(token, public_key, algorithms=["RS256"], audience=audience)


FORM_CODE = {
    "grant_type": "authorization_code",
    "code": "authorization-code-value",
    "redirect_uri": REDIRECT_URI,
    "code_verifier": VERIFIER,
    "client_id": CLIENT_ID,
}


class TestAuthorizationCodeGrant:
    async def test_happy_path_issues_verified_token_triple(self) -> None:
        key_row, public_key = _key_harness()
        session = MagicMock()
        session.get = AsyncMock(return_value=MagicMock(id=USER_ID, is_active=True))
        patches = _grant_patches(key_row, client_row())
        with (
            patches[0],
            patches[1],
            patches[2],
            patches[3],
            patch.object(oidc_repo, "get_grant_code_by_hash", AsyncMock(return_value=_code_row(scope="openid phone offline_access"))),
            patch.object(oidc_repo, "consume_grant_code", AsyncMock(return_value=True)) as consume,
            patch.object(oidc_repo, "create_refresh_token", AsyncMock(return_value=MagicMock())),
        ):
            response = await gv.token(session, _request(), dict(FORM_CODE))

        assert response["token_type"] == "Bearer"
        assert response["expires_in"] == 3600
        assert response["scope"] == "openid phone offline_access"
        access = _decode(response["access_token"], public_key, AUDIENCE)
        assert access["sub"] == str(USER_ID)
        assert access["client_id"] == CLIENT_ID
        assert access["auth_provider"] == "oidc"
        assert access["auth_time"] == pytest.approx(1760000000.0)
        assert pyjwt.get_unverified_header(response["access_token"])["kid"] == key_row.kid

        id_claims = _decode(response["id_token"], public_key, CLIENT_ID)
        assert id_claims["azp"] == CLIENT_ID
        assert id_claims["nonce"] == "n-123"
        assert id_claims["auth_time"] == pytest.approx(1760000000.0)
        assert id_claims["amr"] == ["pwd"]
        assert id_claims["acr"] == "urn:swx:acr:pwd"
        assert id_claims["at_hash"] == oidc_tokens._at_hash(response["access_token"])

        assert len(response["refresh_token"]) > 40
        consume.assert_awaited_once()

    async def test_refresh_absent_without_offline_access(self) -> None:
        """A6: refresh tokens are only minted when the offline_access scope was requested."""
        key_row, _ = _key_harness()
        session = MagicMock()
        session.get = AsyncMock(return_value=MagicMock(id=USER_ID, is_active=True))
        patches = _grant_patches(key_row, client_row())
        with (
            patches[0],
            patches[1],
            patches[2],
            patches[3],
            patch.object(oidc_repo, "get_grant_code_by_hash", AsyncMock(return_value=_code_row())),
            patch.object(oidc_repo, "consume_grant_code", AsyncMock(return_value=True)) as consume,
            patch.object(oidc_repo, "create_refresh_token", AsyncMock()) as create_refresh,
        ):
            response = await gv.token(session, _request(), dict(FORM_CODE))

        assert "refresh_token" not in response
        create_refresh.assert_not_awaited()
        consume.assert_awaited_once()

    async def test_replay_refused_and_audited(self) -> None:
        key_row, _ = _key_harness()
        session = MagicMock()
        patches = _grant_patches(key_row, client_row())
        with (
            patches[0],
            patches[1],
            patches[2],
            patches[3] as audit_logger,
            patch.object(oidc_repo, "get_grant_code_by_hash", AsyncMock(return_value=_code_row(scope="openid phone offline_access"))),
            patch.object(oidc_repo, "consume_grant_code", AsyncMock(return_value=False)),
        ):
            audit_logger.return_value.log_event = AsyncMock()
            with pytest.raises(OIDCAuthzError, match="already redeemed"):
                await gv.token(session, _request(), dict(FORM_CODE))
            assert audit_logger.return_value.log_event.await_args.kwargs["outcome"].value == "failure"

    async def test_redirect_mismatch_burns_the_code(self) -> None:
        key_row, _ = _key_harness()
        session = MagicMock()
        patches = _grant_patches(key_row, client_row())
        with (
            patches[0],
            patches[1],
            patches[2],
            patches[3],
            patch.object(oidc_repo, "get_grant_code_by_hash", AsyncMock(return_value=_code_row(scope="openid phone offline_access"))),
            patch.object(oidc_repo, "consume_grant_code", AsyncMock(return_value=True)) as consume,
        ):
            with pytest.raises(OIDCAuthzError, match="does not match"):
                await gv.token(session, _request(), dict(FORM_CODE) | {"redirect_uri": "https://app.example.com/other"})
        consume.assert_awaited_once()

    async def test_other_clients_code_refused_without_consuming(self) -> None:
        key_row, _ = _key_harness()
        session = MagicMock()
        patches = _grant_patches(key_row, client_row())
        with (
            patches[0],
            patches[1],
            patches[2],
            patches[3],
            patch.object(oidc_repo, "get_grant_code_by_hash", AsyncMock(return_value=_code_row(client_id=OTHER_CLIENT_ID))),
            patch.object(oidc_repo, "consume_grant_code", AsyncMock(return_value=True)) as consume,
        ):
            with pytest.raises(OIDCAuthzError, match="Unknown authorization code"):
                await gv.token(session, _request(), dict(FORM_CODE))
        consume.assert_not_awaited()

    async def test_expired_code_refused_without_consuming(self) -> None:
        key_row, _ = _key_harness()
        session = MagicMock()
        patches = _grant_patches(key_row, client_row())
        with (
            patches[0],
            patches[1],
            patches[2],
            patches[3],
            patch.object(
                oidc_repo, "get_grant_code_by_hash", AsyncMock(return_value=_code_row(expires_at=utc_now() - timedelta(seconds=1)))
            ),
            patch.object(oidc_repo, "consume_grant_code", AsyncMock(return_value=True)) as consume,
        ):
            with pytest.raises(OIDCAuthzError, match="expired"):
                await gv.token(session, _request(), dict(FORM_CODE))
        consume.assert_not_awaited()

    async def test_pkce_verifier_mismatch_refused(self) -> None:
        key_row, _ = _key_harness()
        session = MagicMock()
        patches = _grant_patches(key_row, client_row())
        with (
            patches[0],
            patches[1],
            patches[2],
            patches[3],
            patch.object(oidc_repo, "get_grant_code_by_hash", AsyncMock(return_value=_code_row(scope="openid phone offline_access"))),
            patch.object(oidc_repo, "consume_grant_code", AsyncMock(return_value=True)) as consume,
        ):
            with pytest.raises(OIDCAuthzError, match="PKCE verification failed"):
                await gv.token(session, _request(), dict(FORM_CODE) | {"code_verifier": "z" * 45})

        consume.assert_awaited_once()

class TestRefreshTokenGrant:
    def _refresh_row(self, **overrides: object) -> MagicMock:
        row = MagicMock(
            id=REFRESH_ID,
            family_id=FAMILY_ID,
            client_id=CLIENT_ID,
            user_id=USER_ID,
            scope="openid phone",
            status="active",
            auth_time=AUTH_TIME,
            expires_at=utc_now() + timedelta(seconds=1000),
            token_hash=oidc_tokens.sha256_hex("old-refresh-value"),
        )
        for key, value in overrides.items():
            setattr(row, key, value)
        return row

    async def test_refresh_clamps_to_registered_scopes(self) -> None:
        """M-3: admin scope narrowing propagates on refresh (no privilege persistence)."""
        key_row, _ = _key_harness()
        session = MagicMock()
        restricted = client_row(scopes=["openid"])
        patches = _grant_patches(key_row, restricted)
        with (
            patches[0],
            patches[1],
            patches[2],
            patches[3],
            patch.object(oidc_repo, "get_refresh_token_by_hash", AsyncMock(return_value=self._refresh_row())),
            patch.object(oidc_repo, "rotate_refresh_tokens", AsyncMock(return_value=MagicMock(id=uuid.uuid4()))) as rotate,
        ):
            response = await gv.token(session, _request(), {"grant_type": "refresh_token", "refresh_token": "old-refresh-value"})

        assert response["scope"] == "openid"
        assert rotate.await_args.kwargs["new_data"]["scope"] == "openid"

    async def test_refresh_with_fully_stripped_scopes_refused(self) -> None:
        key_row, _ = _key_harness()
        session = MagicMock()
        stripped = client_row(scopes=[])
        patches = _grant_patches(key_row, stripped)
        with (
            patches[0],
            patches[1],
            patches[2],
            patches[3],
            patch.object(oidc_repo, "get_refresh_token_by_hash", AsyncMock(return_value=self._refresh_row())),
            patch.object(oidc_repo, "rotate_refresh_tokens", AsyncMock(return_value=MagicMock(id=uuid.uuid4()))) as rotate,
        ):
            with pytest.raises(OIDCAuthzError, match="invalid_scope"):
                await gv.token(session, _request(), {"grant_type": "refresh_token", "refresh_token": "old-refresh-value"})

        rotate.assert_not_awaited()

    async def test_missing_code_is_invalid_request(self) -> None:
        key_row, _ = _key_harness()
        session = MagicMock()
        patches = _grant_patches(key_row, client_row())
        with patches[0], patches[1], patches[2], patches[3]:
            with pytest.raises(OIDCAuthzError, match="code is required"):
                await gv.token(session, _request(), {"grant_type": "authorization_code", "client_id": CLIENT_ID})


    async def test_rotates_in_place_and_issues_new_family_member(self) -> None:
        key_row, public_key = _key_harness()
        session = MagicMock()
        patches = _grant_patches(key_row, client_row())
        with (
            patches[0],
            patches[1],
            patches[2],
            patches[3],
            patch.object(oidc_repo, "get_refresh_token_by_hash", AsyncMock(return_value=self._refresh_row())),
            patch.object(oidc_repo, "rotate_refresh_tokens", AsyncMock(return_value=MagicMock(id=uuid.uuid4()))) as rotate,
        ):
            response = await gv.token(session, _request(), {"grant_type": "refresh_token", "refresh_token": "old-refresh-value"})

        assert response["refresh_token"] != "old-refresh-value"
        kwargs = rotate.await_args.kwargs
        assert kwargs["old_id"] == REFRESH_ID
        assert kwargs["new_data"]["family_id"] == FAMILY_ID
        assert kwargs["new_data"]["token_hash"] == oidc_tokens.sha256_hex(response["refresh_token"])

        id_claims = _decode(response["id_token"], public_key, CLIENT_ID)
        assert "nonce" not in id_claims
        assert id_claims["auth_time"] == pytest.approx(1760000000.0)

    async def test_reuse_of_rotated_token_revokes_whole_family(self) -> None:
        key_row, _ = _key_harness()
        session = MagicMock()
        patches = _grant_patches(key_row, client_row())
        with (
            patches[0],
            patches[1],
            patches[2],
            patches[3] as audit_logger,
            patch.object(oidc_repo, "get_refresh_token_by_hash", AsyncMock(return_value=self._refresh_row(status="rotated"))),
            patch.object(oidc_repo, "revoke_family", AsyncMock(return_value=2)) as revoke_family,
        ):
            audit_logger.return_value.log_event = AsyncMock()
            with pytest.raises(OIDCAuthzError, match="reuse detected"):
                await gv.token(session, _request(), {"grant_type": "refresh_token", "refresh_token": "old-refresh-value"})

        revoke_family.assert_awaited_once_with(session, FAMILY_ID)
        actions = [call.kwargs["action"] for call in audit_logger.return_value.log_event.await_args_list]
        assert "auth.token_family_revoked" in actions
        assert "auth.oidc_token_denied" in actions

    async def test_rotation_race_is_treated_as_reuse(self) -> None:
        key_row, _ = _key_harness()
        session = MagicMock()
        patches = _grant_patches(key_row, client_row())
        with (
            patches[0],
            patches[1],
            patches[2],
            patches[3],
            patch.object(oidc_repo, "get_refresh_token_by_hash", AsyncMock(return_value=self._refresh_row())),
            patch.object(oidc_repo, "rotate_refresh_tokens", AsyncMock(return_value=None)),
            patch.object(oidc_repo, "revoke_family", AsyncMock(return_value=1)) as revoke_family,
        ):
            with pytest.raises(OIDCAuthzError, match="reuse detected"):
                await gv.token(session, _request(), {"grant_type": "refresh_token", "refresh_token": "old-refresh-value"})
        revoke_family.assert_awaited_once()

    async def test_unknown_refresh_token_refused(self) -> None:
        key_row, _ = _key_harness()
        session = MagicMock()
        patches = _grant_patches(key_row, client_row())
        with (
            patches[0],
            patches[1],
            patches[2],
            patches[3],
            patch.object(oidc_repo, "get_refresh_token_by_hash", AsyncMock(return_value=None)),
        ):
            with pytest.raises(OIDCAuthzError, match="Unknown refresh token"):
                await gv.token(session, _request(), {"grant_type": "refresh_token", "refresh_token": "nope"})

    async def test_other_clients_refresh_token_refused(self) -> None:
        key_row, _ = _key_harness()
        session = MagicMock()
        patches = _grant_patches(key_row, client_row())
        with (
            patches[0],
            patches[1],
            patches[2],
            patches[3],
            patch.object(oidc_repo, "get_refresh_token_by_hash", AsyncMock(return_value=self._refresh_row(client_id=OTHER_CLIENT_ID))),
            patch.object(oidc_repo, "revoke_family", AsyncMock(return_value=0)) as revoke_family,
        ):
            with pytest.raises(OIDCAuthzError, match="Unknown refresh token"):
                await gv.token(session, _request(), {"grant_type": "refresh_token", "refresh_token": "stolen"})

        revoke_family.assert_not_awaited()


class TestClientCredentialsGrant:
    async def test_confidential_first_party_issues_machine_token(self) -> None:
        key_row, public_key = _key_harness()
        session = MagicMock()
        confidential = client_row(client_secret_hash="$2b$12$dummy", is_first_party=True)
        patches = _grant_patches(key_row, confidential)
        with patches[0], patches[1], patches[2], patches[3]:
            response = await gv.token(
                session, _request(), {"grant_type": "client_credentials", "client_id": CLIENT_ID, "client_secret": "s3cret", "scope": "phone"}
            )

        assert "refresh_token" not in response
        assert "id_token" not in response
        assert response["scope"] == "phone"
        claims = _decode(response["access_token"], public_key, AUDIENCE)
        assert claims["sub"] == CLIENT_ID
        assert claims["scope"] == "phone"

    async def test_public_client_refused(self) -> None:
        key_row, _ = _key_harness()
        session = MagicMock()
        patches = _grant_patches(key_row, client_row())
        with patches[0], patches[1], patches[2], patches[3]:
            with pytest.raises(OIDCAuthzError, match="confidential"):
                await gv.token(session, _request(), {"grant_type": "client_credentials", "client_id": CLIENT_ID})

    async def test_scope_escalation_refused(self) -> None:
        key_row, _ = _key_harness()
        session = MagicMock()
        confidential = client_row(client_secret_hash="$2b$12$dummy", is_first_party=True)
        patches = _grant_patches(key_row, confidential)
        with patches[0], patches[1], patches[2], patches[3]:
            with pytest.raises(OIDCAuthzError, match="invalid_scope"):
                await gv.token(
                    session,
                    _request(),
                    {"grant_type": "client_credentials", "client_id": CLIENT_ID, "client_secret": "s3cret", "scope": "phone admin"},
                )

    async def test_unsupported_grant_type(self) -> None:
        key_row, _ = _key_harness()
        session = MagicMock()
        patches = _grant_patches(key_row, client_row())
        with patches[0], patches[1], patches[2], patches[3]:
            with pytest.raises(OIDCAuthzError, match="unsupported_grant_type"):
                await gv.token(session, _request(), {"grant_type": "password", "client_id": CLIENT_ID})

    async def test_signing_unavailable_is_audited(self) -> None:
        key_row, _ = _key_harness()
        session = MagicMock()
        confidential = client_row(client_secret_hash="$2b$12$dummy", is_first_party=True)
        audit = _audit_mock()
        with (
            patch.object(oidc_repo, "get_active_signing_key", AsyncMock(return_value=None)),
            patch.object(oidc_security, "authenticate_client", AsyncMock(return_value=confidential)),
            patch.object(gv, "AuditLogger", return_value=audit),
        ):
            with pytest.raises(oidc_tokens.OIDCSigningUnavailable):
                await gv.token(
                    session, _request(), {"grant_type": "client_credentials", "client_id": CLIENT_ID, "client_secret": "s3cret"}
                )

        assert audit.log_event.await_args.kwargs["action"] == AuditAction.AUTH_OIDC_TOKEN_DENIED
        assert audit.log_event.await_args.kwargs["context"]["error"] == "temporarily_unavailable"