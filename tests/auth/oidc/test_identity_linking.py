# pyright: reportAny=false, reportExplicitAny=false, reportUnknownMemberType=false, reportUnknownArgumentType=false, reportMissingImports=false, reportUnusedCallResult=false, reportAttributeAccessIssue=false, reportArgumentType=false, reportCallIssue=false

"""
Unit tests for SWX-IDM-001 D-7: external-identity linking over swx_social_accounts.
"""

import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from swx_core.auth.oidc_provider import identity_linking as il
from swx_core.models.social_account import SocialAccount
from swx_core.services.audit_logger import AuditAction, AuditOutcome

pytestmark = pytest.mark.unit

IDP = "afcloud"
SUB = "afcloud-sub-123"


def _audit_mock() -> MagicMock:
    mock = MagicMock()
    mock.log_event = AsyncMock()
    return mock


def _user() -> MagicMock:
    return MagicMock(id=uuid.uuid4(), email="ayo@example.com", is_active=True)


def _session_with_lookup(lookup_result: object) -> MagicMock:
    session = MagicMock()
    session.execute = AsyncMock(
        side_effect=[MagicMock(scalar_one_or_none=MagicMock(return_value=lookup_result))]
    )
    session.add = MagicMock()
    session.commit = AsyncMock()
    session.refresh = AsyncMock()
    return session


class TestLinkExternalIdentity:
    async def test_requires_verified_phone_claim(self) -> None:
        session = _session_with_lookup(None)
        audit = _audit_mock()
        with patch.object(il, "AuditLogger", return_value=audit):
            with pytest.raises(ValueError, match="verified phone"):
                await il.link_external_identity(session, _user(), SUB, IDP, phone_verified_claim=False)

        session.add.assert_not_called()
        kwargs = audit.log_event.await_args.kwargs
        assert kwargs["action"] == AuditAction.AUTH_IDENTITY_LINKED
        assert kwargs["outcome"] == AuditOutcome.FAILURE
        assert kwargs["context"]["reason"].startswith("identity linking requires")

    async def test_links_account_and_audits(self) -> None:
        user = _user()
        session = _session_with_lookup(None)
        audit = _audit_mock()
        with patch.object(il, "AuditLogger", return_value=audit):
            account = await il.link_external_identity(session, user, SUB, IDP, phone_verified_claim=True)

        assert account.provider == IDP
        assert account.provider_id == SUB
        assert account.user_id == user.id
        session.add.assert_called_once()
        session.commit.assert_awaited_once()
        assert audit.log_event.await_args.kwargs["action"] == AuditAction.AUTH_IDENTITY_LINKED

    async def test_idempotent_for_same_user(self) -> None:
        user = _user()
        existing = SocialAccount(provider=IDP, provider_id=SUB, user_id=user.id)
        session = _session_with_lookup(existing)
        with patch.object(il, "AuditLogger", return_value=_audit_mock()):
            account = await il.link_external_identity(session, user, SUB, IDP, phone_verified_claim=True)

        assert account is existing
        session.add.assert_not_called()

    async def test_conflicting_link_refused(self) -> None:
        user = _user()
        other = SocialAccount(provider=IDP, provider_id=SUB, user_id=uuid.uuid4())
        session = _session_with_lookup(other)
        with patch.object(il, "AuditLogger", return_value=_audit_mock()):
            with pytest.raises(ValueError, match="another user"):
                await il.link_external_identity(session, user, SUB, IDP, phone_verified_claim=True)


class TestResolveUserByIdpSub:
    async def test_resolves_owner(self) -> None:
        user = _user()
        session = MagicMock()
        session.execute = AsyncMock(
            side_effect=[MagicMock(scalar_one_or_none=MagicMock(return_value=MagicMock(user_id=user.id)))]
        )
        session.get = AsyncMock(return_value=user)

        assert await il.resolve_user_by_idp_sub(session, SUB, IDP) is user

    async def test_unknown_subject_returns_none(self) -> None:
        session = MagicMock()
        session.execute = AsyncMock(side_effect=[MagicMock(scalar_one_or_none=MagicMock(return_value=None))])

        assert await il.resolve_user_by_idp_sub(session, "missing", IDP) is None

    async def test_other_idp_scoped_out(self) -> None:
        session = MagicMock()
        session.execute = AsyncMock(side_effect=[MagicMock(scalar_one_or_none=MagicMock(return_value=None))])

        assert await il.resolve_user_by_idp_sub(session, SUB, "google") is None

        stmt = session.execute.await_args.args[0]
        compiled_from = str(stmt.compile(compile_kwargs={"literal_binds": False}))
        assert "swx_social_accounts" in compiled_from