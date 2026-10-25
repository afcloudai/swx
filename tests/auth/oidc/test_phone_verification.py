# pyright: reportAny=false, reportExplicitAny=false, reportUnknownMemberType=false, reportUnknownArgumentType=false, reportMissingImports=false, reportUnusedCallResult=false, reportAttributeAccessIssue=false, reportArgumentType=false, reportCallIssue=false

"""
Unit tests for SWX-IDM-001 D-1: phone verification service + route surface.
Uses the REAL framework OTP machinery (in-memory, keyed ``phone:<user_id>``).
"""

import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from swx_core.auth.oidc_provider import phone_verification as phv
from swx_core.config.settings import settings
from swx_core.models.user import User
from swx_core.routes.user.phone_verification_route import router
from swx_core.services.audit_logger import AuditAction
from swx_core.services.auth.email_otp_service import OtpInvalidError
from swx_core.utils.time import utc_now

pytestmark = pytest.mark.unit

PHONE = "+2348012345678"


class CaptureChannel:
    def __init__(self) -> None:
        self.sent: list[dict] = []

    async def send_verification_code(self, *, phone: str, code: str, user_email: str | None = None) -> None:
        self.sent.append({"phone": phone, "code": code, "user_email": user_email})


def _audit_mock() -> MagicMock:
    mock = MagicMock()
    mock.log_event = AsyncMock()
    return mock


def _user(**overrides: object) -> MagicMock:
    data: dict[str, object] = {
        "id": uuid.uuid4(),
        "email": "ayo@example.com",
        "phone": None,
        "phone_verified_at": None,
        "is_active": True,
    }
    data.update(overrides)
    return MagicMock(**data)


def _session() -> MagicMock:
    session = MagicMock()
    session.add = MagicMock()
    session.commit = AsyncMock()
    return session


class TestUserModelFields:
    def test_phone_fields_present_and_nullable(self) -> None:
        user = User(email="ayo@example.com")
        assert user.phone is None
        assert user.phone_verified_at is None


class TestRequestPhoneVerification:
    async def test_invalid_phone_refused_before_any_effect(self) -> None:
        session = _session()
        user = _user()
        audit = _audit_mock()
        with (
            patch.object(settings, "SWX_PHONE_VERIFICATION_CHANNEL", "capture"),
            patch.object(phv, "AuditLogger", return_value=audit),
        ):
            with pytest.raises(ValueError, match="E.164"):
                await phv.request_phone_verification(session, user, "08012345678")

        assert session.commit.await_count == 0

    async def test_request_sets_phone_and_delivers_code(self) -> None:
        session = _session()
        user = _user()
        audit = _audit_mock()
        channel = CaptureChannel()
        phv.register_phone_channel("capture", channel)
        with (
            patch.object(settings, "SWX_PHONE_VERIFICATION_CHANNEL", "capture"),
            patch.object(phv, "AuditLogger", return_value=audit),
        ):
            await phv.request_phone_verification(session, user, PHONE)

        assert user.phone == PHONE
        session.commit.assert_awaited_once()
        assert len(channel.sent) == 1
        code = channel.sent[0]["code"]
        assert code.isdigit() and len(code) == settings.OTP_LENGTH

    async def test_phone_change_clears_verification_state(self) -> None:
        session = _session()
        user = _user(phone_verified_at=utc_now())
        audit = _audit_mock()
        channel = CaptureChannel()
        phv.register_phone_channel("capture", channel)
        with (
            patch.object(settings, "SWX_PHONE_VERIFICATION_CHANNEL", "capture"),
            patch.object(phv, "AuditLogger", return_value=audit),
        ):
            await phv.request_phone_verification(session, user, PHONE)

        assert user.phone_verified_at is None

    async def test_re_request_requires_reconfirm(self) -> None:
        session = _session()
        user = _user(phone_verified_at=utc_now())
        with (
            patch.object(settings, "SWX_PHONE_VERIFICATION_CHANNEL", "capture"),
            patch.object(phv, "AuditLogger", return_value=_audit_mock()),
        ):
            channel = CaptureChannel()
            phv.register_phone_channel("capture", channel)
            await phv.request_phone_verification(session, user, PHONE)

            assert user.phone_verified_at is None
            code = channel.sent[0]["code"]
            await phv.confirm_phone_verification(session, user, code)

        assert user.phone_verified_at is not None


class TestConfirmPhoneVerification:
    async def test_confirm_with_delivered_code_verifies(self) -> None:
        session = _session()
        user = _user()
        audit = _audit_mock()
        with (
            patch.object(settings, "SWX_PHONE_VERIFICATION_CHANNEL", "capture"),
            patch.object(phv, "AuditLogger", return_value=audit),
        ):
            channel = CaptureChannel()
            phv.register_phone_channel("capture", channel)
            await phv.request_phone_verification(session, user, PHONE)
            code = channel.sent[0]["code"]

            await phv.confirm_phone_verification(session, user, code)

        assert user.phone_verified_at is not None
        actions = [call.kwargs["action"] for call in audit.log_event.await_args_list]
        assert AuditAction.AUTH_PHONE_VERIFICATION_CONFIRMED in actions

    async def test_confirm_wrong_code_refused(self) -> None:
        session = _session()
        user = _user()
        with (
            patch.object(settings, "SWX_PHONE_VERIFICATION_CHANNEL", "capture"),
            patch.object(phv, "AuditLogger", return_value=_audit_mock()),
        ):
            channel = CaptureChannel()
            phv.register_phone_channel("capture", channel)
            await phv.request_phone_verification(session, user, PHONE)

            with pytest.raises(OtpInvalidError, match="Invalid or expired"):
                await phv.confirm_phone_verification(session, user, "000000")

        assert user.phone_verified_at is None

    async def test_confirm_without_request_refused(self) -> None:
        session = _session()
        user = _user()
        with (
            patch.object(settings, "SWX_PHONE_VERIFICATION_CHANNEL", "capture"),
            patch.object(phv, "AuditLogger", return_value=_audit_mock()),
        ):
            with pytest.raises(OtpInvalidError):
                await phv.confirm_phone_verification(session, user, "111111")

        assert user.phone_verified_at is None

    async def test_delivered_code_is_single_use(self) -> None:
        session = _session()
        user = _user()
        with (
            patch.object(settings, "SWX_PHONE_VERIFICATION_CHANNEL", "capture"),
            patch.object(phv, "AuditLogger", return_value=_audit_mock()),
        ):
            channel = CaptureChannel()
            phv.register_phone_channel("capture", channel)
            await phv.request_phone_verification(session, user, PHONE)
            code = channel.sent[0]["code"]

            await phv.confirm_phone_verification(session, user, code)

            with pytest.raises(OtpInvalidError):
                await phv.confirm_phone_verification(session, user, code)


class TestChannelResolution:
    async def test_unknown_channel_name_raises(self) -> None:
        with patch.object(settings, "SWX_PHONE_VERIFICATION_CHANNEL", "missing-channel"):
            with pytest.raises(LookupError, match="not registered"):
                phv.resolve_phone_channel()

    async def test_default_channel_is_logging(self) -> None:
        with patch.object(settings, "SWX_PHONE_VERIFICATION_CHANNEL", None):
            assert isinstance(phv.resolve_phone_channel(), phv.LoggingChannel)


class TestRouteSurface:
    def test_request_and_confirm_mounted(self) -> None:
        paths = {getattr(route, "path", "") for route in router.routes}
        assert paths == {"/user/phone-verification/request", "/user/phone-verification/confirm"}