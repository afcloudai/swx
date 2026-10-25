# pyright: reportAny=false, reportExplicitAny=false, reportUnknownMemberType=false, reportUnknownArgumentType=false, reportMissingImports=false, reportUnusedCallResult=false, reportAttributeAccessIssue=false, reportArgumentType=false, reportCallIssue=false

"""
Unit tests for SWX-IDM-001 D-6/D-8: the client-authentication battery.

``authenticate_client`` is the impersonation gate for /oidc/token and
/oidc/revoke — verified here directly (token-grant tests patch it).
"""

import base64
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from swx_core.auth.oidc_provider import repositories as oidc_repo
from swx_core.auth.oidc_provider import security as oidc_security
from swx_core.auth.oidc_provider.grant_service import OIDCAuthzError
from swx_core.auth.oidc_provider.models import OIDCClient
from swx_core.security.password_security import get_password_hash

pytestmark = pytest.mark.unit

CLIENT_ID = "aabbccddeeff00112233445566778899"
SECRET = "confidential-s3cret"


def _request(*, headers: dict | None = None, query: dict | None = None) -> MagicMock:
    request = MagicMock()
    request.headers = headers or {}
    request.cookies = {}
    request.query_params = query or {}
    request.session = {}
    request.base_url = "https://idp.example.com/"
    return request


def _basic(client_id: str, secret: str) -> dict[str, str]:
    token = base64.b64encode(f"{client_id}:{secret}".encode()).decode()
    return {"Authorization": f"Basic {token}"}


def _form(client_id: str, secret: str | None = None) -> dict[str, Any]:
    if secret is None:
        return {"client_id": client_id}
    return {"client_id": client_id, "client_secret": secret}


async def _confidential_row(**overrides: Any) -> OIDCClient:
    data: dict[str, Any] = {
        "name": "Confidential RP",
        "client_id": CLIENT_ID,
        "client_secret_hash": await get_password_hash(SECRET),
        "redirect_uris": ["https://app.example.com/callback"],
        "grant_types": ["authorization_code", "refresh_token", "client_credentials"],
        "scopes": ["openid", "profile", "phone"],
    }
    data.update(overrides)
    return OIDCClient(**data)


def _patched_lookup(row: OIDCClient | None) -> Any:
    return patch.object(oidc_repo, "get_client_by_public_id", AsyncMock(return_value=row))


class TestConfidentialClientAuthentication:
    async def test_basic_auth_happy(self) -> None:
        row = await _confidential_row()
        with _patched_lookup(row):
            client = await oidc_security.authenticate_client(MagicMock(), _request(headers=_basic(CLIENT_ID, SECRET)), {})

        assert client is row

    async def test_body_secret_happy(self) -> None:
        row = await _confidential_row()
        with _patched_lookup(row):
            client = await oidc_security.authenticate_client(MagicMock(), _request(), _form(CLIENT_ID, SECRET))

        assert client is row

    async def test_wrong_secret_refused_401(self) -> None:
        row = await _confidential_row()
        with _patched_lookup(row):
            with pytest.raises(OIDCAuthzError, match="Client authentication failed") as exc_info:
                await oidc_security.authenticate_client(MagicMock(), _request(headers=_basic(CLIENT_ID, "wrong")), {})
        assert exc_info.value.status_code == 401

    async def test_unknown_client_refused_401(self) -> None:
        with _patched_lookup(None):
            with pytest.raises(OIDCAuthzError, match="Client authentication failed"):
                await oidc_security.authenticate_client(
                    MagicMock(), _request(headers=_basic(CLIENT_ID, SECRET)), {}
                )

    async def test_disabled_client_refused_401(self) -> None:
        row = await _confidential_row(enabled=False)
        with _patched_lookup(row):
            with pytest.raises(OIDCAuthzError, match="Client authentication failed"):
                await oidc_security.authenticate_client(MagicMock(), _request(headers=_basic(CLIENT_ID, SECRET)), {})


class TestPublicClientAuthentication:
    async def test_secretless_body_happy(self) -> None:
        row = await _confidential_row(client_secret_hash=None)
        with _patched_lookup(row):
            client = await oidc_security.authenticate_client(MagicMock(), _request(), _form(CLIENT_ID))

        assert client is row

    async def test_secret_present_for_public_client_refused_401(self) -> None:
        row = await _confidential_row(client_secret_hash=None)
        with _patched_lookup(row):
            with pytest.raises(OIDCAuthzError, match="Client authentication failed"):
                await oidc_security.authenticate_client(MagicMock(), _request(), _form(CLIENT_ID, SECRET))


class TestHardeningRules:
    async def test_query_string_secret_refused_400(self) -> None:
        row = await _confidential_row()
        with _patched_lookup(row):
            with pytest.raises(OIDCAuthzError, match="must not be sent in the query string") as exc_info:
                await oidc_security.authenticate_client(
                    MagicMock(), _request(headers=_basic(CLIENT_ID, SECRET), query={"client_secret": SECRET}), {}
                )
        assert exc_info.value.status_code == 400

    async def test_multiple_auth_methods_refused_400(self) -> None:
        """RFC 6749 §2.3: credentials in more than one way ⇒ reject (L-2)."""
        row = await _confidential_row()
        with _patched_lookup(row):
            with pytest.raises(OIDCAuthzError, match="multiple client authentication methods") as exc_info:
                await oidc_security.authenticate_client(
                    MagicMock(), _request(headers=_basic(CLIENT_ID, SECRET)), _form(CLIENT_ID, SECRET)
                )
        assert exc_info.value.status_code == 400

    async def test_unknown_client_refusal_costs_bcrypt_too(self) -> None:
        """L-3: the unknown-client refusal runs a dummy bcrypt (timing equalization)."""
        row = await _confidential_row()
        with (
            _patched_lookup(None),
            patch.object(oidc_security, "verify_password", AsyncMock(return_value=False)) as verify,
        ):
            with pytest.raises(OIDCAuthzError, match="Client authentication failed"):
                await oidc_security.authenticate_client(MagicMock(), _request(headers=_basic(CLIENT_ID, SECRET)), {})

        assert verify.await_count == 1

    async def test_missing_credentials_refused_401(self) -> None:
        row = await _confidential_row()
        with _patched_lookup(row):
            with pytest.raises(OIDCAuthzError, match="Client authentication required"):
                await oidc_security.authenticate_client(MagicMock(), _request(), {})
            with pytest.raises(OIDCAuthzError, match="Client authentication required"):
                await oidc_security.authenticate_client(MagicMock(), _request(), {"grant_type": "authorization_code"})

    async def test_malformed_basic_header_refused_401(self) -> None:
        row = await _confidential_row()
        with _patched_lookup(row):
            with pytest.raises(OIDCAuthzError, match="Malformed Basic"):
                await oidc_security.authenticate_client(MagicMock(), _request(headers={"Authorization": "Basic !!!"}), {})

    async def test_secret_verifier_for_confidential_client_enforced(self) -> None:
        row = await _confidential_row()
        with _patched_lookup(row):
            with pytest.raises(OIDCAuthzError, match="Client authentication failed") as exc_info:
                await oidc_security.authenticate_client(MagicMock(), _request(), _form(CLIENT_ID))
        assert exc_info.value.status_code == 401