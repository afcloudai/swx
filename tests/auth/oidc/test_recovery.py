# pyright: reportAny=false, reportExplicitAny=false, reportUnknownMemberType=false, reportUnknownArgumentType=false, reportMissingImports=false, reportUnusedCallResult=false, reportAttributeAccessIssue=false, reportArgumentType=false, reportCallIssue=false

"""
Conformance/recovery tests for D-9: phone-OTP account recovery.
"""

import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from swx_core.auth.oidc_provider import recovery as recovery_service
from swx_core.auth.oidc_provider import repositories as oidc_repo
from swx_core.models.user import User
from swx_core.services.audit_logger import AuditAction, AuditOutcome
from swx_core.services.auth.email_otp_service import OtpInvalidError
from swx_core.utils.time import utc_now

pytestmark = pytest.mark.unit

PHONE = "+2348012345678"


def _audit_mock() -> MagicMock:
    mock = MagicMock()
    mock.log_event = AsyncMock()
    return mock


def _user() -> MagicMock:
    return MagicMock(id=uuid.uuid4(), email="ayo@example.com", phone=PHONE, phone_verified_at=utc_now(), hashed_password="old")


def _capture():
    channel = MagicMock()
    channel.codes: list = []  # pyright: ignore[reportAttributeAccessIssue]
    channel.send_verification_code = AsyncMock(
        side_effect=lambda **kw: (channel.codes.append(kw), None)[1]
    )
    return channel


class TestRecoveryRequest:
    async def test_unknown_phone_is_silent_and_identical(self) -> None:
        channel = _capture()
        session = MagicMock()
        with (
            patch.object(oidc_repo, "find_user_by_verified_phone", AsyncMock(return_value=None)),
            patch.object(recovery_service, "resolve_phone_channel", return_value=channel),
        ):
            result = await recovery_service.request_phone_recovery(session, "+19990000000", request=None)

        assert result == {"status": "processed"}
        channel.send_verification_code.assert_not_awaited()

    async def test_verified_phone_receives_recovery_code(self) -> None:
        user = _user()
        channel = _capture()
        session = MagicMock()
        audit = _audit_mock()
        with (
            patch.object(oidc_repo, "find_user_by_verified_phone", AsyncMock(return_value=user)),
            patch.object(recovery_service, "resolve_phone_channel", return_value=channel),
            patch.object(recovery_service, "AuditLogger", return_value=audit),
        ):
            result = await recovery_service.request_phone_recovery(session, PHONE)

        assert result == {"status": "processed"}
        delivered = channel.codes[0]
        assert delivered["phone"] == PHONE
        assert len(delivered["code"]) == 6 and delivered["code"].isdigit()
        actions = [call.kwargs["action"] for call in audit.log_event.await_args_list]
        assert AuditAction.AUTH_PHONE_RECOVERY_REQUESTED in actions


class TestRecoveryConfirm:
    async def test_correct_code_resets_and_revokes_everything(self) -> None:
        user = _user()
        channel = _capture()
        session = MagicMock()
        session.add = MagicMock()
        session.commit = AsyncMock()
        audit = _audit_mock()
        with (
            patch.object(oidc_repo, "find_user_by_verified_phone", AsyncMock(return_value=user)),
            patch.object(recovery_service, "resolve_phone_channel", return_value=channel),
            patch.object(recovery_service, "AuditLogger", return_value=audit),
        ):
            await recovery_service.request_phone_recovery(session, PHONE)
        delivered_code = channel.codes[0]["code"]  # REAL OTP machinery: delivered == storable

        families = AsyncMock(return_value=2)
        revoke_platform = AsyncMock()
        with (
            patch.object(oidc_repo, "find_user_by_verified_phone", AsyncMock(return_value=user)),
            patch.object(recovery_service, "AuditLogger", return_value=audit),
            patch("swx_core.security.refresh_token_service.revoke_all_tokens", revoke_platform),
            patch.object(oidc_repo, "revoke_families_for_user", new=families),
        ):
            result = await recovery_service.confirm_phone_recovery(
                session, phone=PHONE, code=delivered_code, new_password="new-password-9", request=None
            )

        assert result == {"status": "reset"}
        assert user.hashed_password.startswith("$2b$")
        revoke_platform.assert_awaited_once()
        assert families.await_args.args[1] == user.id
        assert AuditAction.AUTH_PHONE_RECOVERY_COMPLETED in [c.kwargs["action"] for c in audit.log_event.await_args_list]

    async def test_wrong_code_refused_and_audited(self) -> None:
        user = _user()
        channel = _capture()
        session = MagicMock()
        audit = _audit_mock()
        with (
            patch.object(oidc_repo, "find_user_by_verified_phone", AsyncMock(return_value=user)),
            patch.object(recovery_service, "resolve_phone_channel", return_value=channel),
            patch.object(recovery_service, "AuditLogger", return_value=audit),
        ):
            await recovery_service.request_phone_recovery(session, PHONE)
            delivered_code = channel.codes[0]["code"]

            with pytest.raises(OtpInvalidError, match="Invalid or expired"):
                await recovery_service.confirm_phone_recovery(
                    session, phone=PHONE, code="000000", new_password="new-password-9"
                )

        failures = [c for c in audit.log_event.await_args_list if c.kwargs["action"] == AuditAction.AUTH_PHONE_RECOVERY_COMPLETED]
        assert failures and failures[0].kwargs["outcome"] == AuditOutcome.FAILURE


class TestModelSurface:
    def test_email_is_nullable_and_phone_fields_exist(self) -> None:
        user = User(email=None)
        assert user.email is None
        assert user.phone is None and user.phone_verified_at is None and user.email_verified_at is None


class TestRecoveryRouteSurface:
    def test_request_and_confirm_mounted(self) -> None:
        from swx_core.routes.access.recovery_route import router

        paths = {getattr(route, "path", "") for route in router.routes}
        assert paths == {"/auth/recovery/request", "/auth/recovery/confirm"}