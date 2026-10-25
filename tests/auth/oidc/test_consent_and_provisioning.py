# pyright: reportAny=false, reportExplicitAny=false, reportUnknownMemberType=false, reportUnknownArgumentType=false, reportMissingImports=false, reportUnusedCallResult=false, reportAttributeAccessIssue=false, reportArgumentType=false, reportCallIssue=false

"""
Consent-surface + federated-provisioning tests (v2.31 Stage-1 linking).
"""

import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from swx_core.auth.oidc_provider import identity_linking as il
from swx_core.auth.oidc_provider import repositories as oidc_repo
from swx_core.models.social_account import SocialAccount
from swx_core.models.user import User
from swx_core.routes.user.oidc_consent_route import router
from swx_core.services.audit_logger import AuditAction
from swx_core.utils.time import utc_now

pytestmark = pytest.mark.unit


def _audit_mock() -> MagicMock:
    mock = MagicMock()
    mock.log_event = AsyncMock()
    return mock


def _consent(**overrides: object) -> object:
    class Row:
        pass

    row = Row()
    row.id = uuid.uuid4()
    row.user_id = uuid.uuid4()
    row.client_id = "aabbcc"
    row.scope = "openid phone"
    row.granted_at = utc_now()
    row.revoked_at = None
    for key, value in overrides.items():
        setattr(row, key, value)
    return row


class TestConsentSurface:
    def test_routes_mounted(self) -> None:
        paths = {getattr(route, "path", "") for route in router.routes}
        assert paths == {"/user/oidc-consents/", "/user/oidc-consents/{client_id}"}

    async def test_list_maps_public_schema(self) -> None:
        rows = [_consent(), _consent(revoked_at=utc_now())]
        session = MagicMock()
        result = MagicMock()
        result.scalars.return_value.all.return_value = rows
        session.execute = AsyncMock(return_value=result)
        consents = await oidc_repo.list_consents_for_user(session, uuid.uuid4())
        assert len(consents) == 2

    def test_public_schema_roundtrip(self) -> None:
        from swx_core.auth.oidc_provider.models import OIDCConsentPublic

        row = _consent()
        public = OIDCConsentPublic.model_validate(row)
        assert public.scope == "openid phone"
        assert public.revoked_at is None


class TestProvisionFederatedIdentity:
    async def test_provisions_emailless_verified_linked_identity(self) -> None:
        session = MagicMock()
        session.add = MagicMock()
        session.commit = AsyncMock()
        session.refresh = AsyncMock()
        session.execute = AsyncMock(
            side_effect=[MagicMock(scalar_one_or_none=MagicMock(return_value=None))]
        )
        audit = _audit_mock()
        with patch.object(il, "AuditLogger", return_value=audit):
            user = await il.provision_federated_identity(
                session, idp="afcloud", idp_sub="afc-sub-1", phone="+2348012345678", full_name="Ayo Ade"
            )

        assert user.email is None
        assert user.hashed_password is None
        assert user.phone == "+2348012345678"
        assert user.phone_verified_at is not None
        assert user.auth_provider == "afcloud"
        assert audit.log_event.await_args.kwargs["action"] == AuditAction.AUTH_IDENTITY_LINKED

    async def test_provision_requires_phone_claim(self) -> None:
        audit = _audit_mock()
        session = MagicMock()
        with patch.object(il, "AuditLogger", return_value=audit):
            with pytest.raises(ValueError, match="phone claim"):
                await il.provision_federated_identity(session, idp="afcloud", idp_sub="s", phone=None)


class TestEmailOptionalModel:
    def test_user_creation_with_null_email(self) -> None:
        user = User(email=None)
        assert user.email is None
        assert user.auth_provider == "local"

    def test_social_account_link_shape(self) -> None:
        account = SocialAccount(provider="afcloud", provider_id="sub-x", user_id=None)
        assert account.provider == "afcloud"