# pyright: reportAny=false, reportExplicitAny=false, reportUnknownMemberType=false, reportUnknownArgumentType=false, reportMissingImports=false, reportUnusedCallResult=false, reportAttributeAccessIssue=false, reportArgumentType=false, reportCallIssue=false

"""
D-10 conformance: phone-first platform sessions.

- phone/password login (``POST /auth/phone/login`` service path)
- email-or-phone ``sub`` minting + phone-only personas resolving via ``sub = phone``
- notifications-backed email OTP transport (``SWX_EMAIL_OTP_CHANNEL=notifications``)
"""

import uuid
from datetime import timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import jwt
import pytest

from swx_core.auth.oidc_provider import identity_verification as iv
from swx_core.auth.oidc_provider import phone_verification as phv
from swx_core.repositories.user_repository import get_user_by_phone
from swx_core.services.auth_service import login_phone_user_service, login_social_user_service
from swx_core.utils.time import utc_now

pytestmark = pytest.mark.unit

PHONE = "+2348012345678"
EMAIL = "ayo@example.com"


def _audit_mock() -> MagicMock:
    mock = MagicMock()
    mock.log_event = AsyncMock()
    return mock


def _user(**overrides: object) -> MagicMock:
    data: dict[str, object] = {
        "id": uuid.uuid4(),
        "email": None,
        "phone": PHONE,
        "phone_verified_at": utc_now(),
        "hashed_password": "$2b$12$storedhash",
        "auth_provider": "afcloud",
        "mfa_enabled": False,
        "is_active": True,
        "locked_until": None,
        "failed_login_attempts": 0,
        "tenant_id": None,
        "is_superuser": False,
    }
    data.update(overrides)
    return MagicMock(**data)


def _request() -> MagicMock:
    return MagicMock()


def _login_session(*results: object) -> MagicMock:
    """Session mock for the login path: awaits execute and returns a chainable result."""
    session = MagicMock()
    session.add = MagicMock()
    session.commit = AsyncMock()
    exec_results = [MagicMock(scalar=MagicMock(return_value=0), scalars=MagicMock(return_value=MagicMock(first=MagicMock(return_value=r)))) for r in (results or (None,))]
    session.execute = AsyncMock(side_effect=exec_results if results else None)
    if not results:
        single = MagicMock()
        single.scalar.return_value = 0
        single.scalars.return_value.first.return_value = None
        session.execute = AsyncMock(return_value=single)
    return session


def _service_env(user: object, password_ok: bool = True, mfa_enabled: bool = False) -> tuple:
    audit = _audit_mock()
    patches = (
        patch("swx_core.services.auth_service.get_user_by_email", AsyncMock(return_value=None)),
        patch("swx_core.services.auth_service.get_user_by_phone", AsyncMock(return_value=user)),
        patch("swx_core.services.auth_service.verify_password", AsyncMock(return_value=password_ok)),
        patch("swx_core.services.auth_service.get_user_permissions", AsyncMock(return_value=[])),
        patch("swx_core.services.auth_service.get_user_plan_key", AsyncMock(return_value="free")),
        patch("swx_core.services.auth_service.increment_failed_login_attempts", AsyncMock()),
        patch("swx_core.services.auth.session_service.enforce_concurrent_limit", AsyncMock()),
        patch("swx_core.services.auth_service.create_refresh_token", AsyncMock(return_value="refresh-token-value")),
        patch("swx_core.services.auth_service.AuditLogger", return_value=audit),
        patch("swx_core.events.dispatcher.event_bus", MagicMock(dispatch=AsyncMock())),
        patch("swx_core.services.settings_helper.get_token_expiration", AsyncMock(return_value=timedelta(minutes=15))),
        patch("swx_core.services.auth_service.translate", lambda _request, key: key),
    )
    if mfa_enabled:
        user.mfa_enabled = True
    return patches, audit


class TestPhoneLoginService:
    async def test_phone_only_persona_logs_in_with_sub_phone(self) -> None:
        user = _user()  # email None
        patches, audit = _service_env(user)
        pm = list(patches)
        with pm[0], pm[1], pm[2], pm[3], pm[4], pm[5], pm[6], pm[7], pm[8], pm[9], pm[10], pm[11]:
            response = await login_phone_user_service(_login_session(), PHONE, "correct-password-9", request=_request())

        assert response.mfa_required is False and response.refresh_token == "refresh-token-value"
        payload = jwt.decode(response.access_token, options={"verify_signature": False})
        assert payload["sub"] == PHONE  # D-10: phone-only personas use sub = phone
        assert audit.log_event.await_args_list[-1].kwargs["context"]["auth_method"] == "phone_password"

    async def test_email_persona_keeps_sub_email(self) -> None:
        user = _user(email=EMAIL)
        patches, audit = _service_env(user)
        pm = list(patches)
        with pm[0], pm[1], pm[2], pm[3], pm[4], pm[5], pm[6], pm[7], pm[8], pm[9], pm[10], pm[11]:
            response = await login_phone_user_service(_login_session(), PHONE, "correct-password-9", request=_request())

        payload = jwt.decode(response.access_token, options={"verify_signature": False})
        assert payload["sub"] == EMAIL
        _ = audit

    async def test_wrong_password_refused_and_audited(self) -> None:
        from fastapi import HTTPException

        user = _user()
        patches, audit = _service_env(user, password_ok=False)
        pm = list(patches)
        with pm[0], pm[1], pm[2], pm[3], pm[4], pm[5], pm[6], pm[7], pm[8], pm[9], pm[10], pm[11]:
            with pytest.raises(HTTPException, match="incorrect"):
                await login_phone_user_service(_login_session(), PHONE, "wrong-password-1", request=_request())

        failures = [c for c in audit.log_event.await_args_list
                    if c.kwargs.get("context") and c.kwargs["context"].get("reason") == "invalid_credentials"]
        assert failures

    async def test_mfa_persona_gets_challenge(self) -> None:
        from fastapi import HTTPException

        user = _user(mfa_enabled=True)
        patches, audit = _service_env(user, mfa_enabled=True)
        pm = list(patches)
        with pm[0], pm[1], pm[2], pm[3], pm[4], pm[5], pm[6], pm[7], pm[8], pm[9], pm[10], pm[11]:
            response = await login_phone_user_service(_login_session(), PHONE, "correct-password-9", request=_request())

        assert response.mfa_required is True and response.mfa_token
        _ = audit


class TestLoginSocialPhoneResolution:
    async def test_social_login_resolves_linked_phone_persona(self) -> None:
        """Stage-1 completion: subject resolution tries email, falls back to verified phone."""
        user = _user()  # email None → phone fallback
        audit = _audit_mock()
        session = MagicMock()

        patches, audit = _service_env(user)
        pm = list(patches)
        pm = list(patches)
        with (
            pm[0],  # get_user_by_email → None (email-less persona)
            pm[1],  # get_user_by_phone → linked persona
            pm[3],  # get_user_permissions → [] (avoids RBAC role join on the mock session)
            pm[7],  # create_refresh_token (auth_service namespace)
            patch("swx_core.services.auth.session_service.enforce_concurrent_limit", AsyncMock()),
            patch("swx_core.events.dispatcher.event_bus", MagicMock(dispatch=AsyncMock())),
            patch("swx_core.services.settings_helper.get_token_expiration", AsyncMock(return_value=timedelta(minutes=15))),
            patch("swx_core.services.billing.plan_helper.get_user_plan_key", AsyncMock(return_value="free")),
        ):
            token = await login_social_user_service(session, PHONE)

        assert token.access_token
        payload = jwt.decode(token.access_token, options={"verify_signature": False})
        assert payload["sub"] == PHONE


class TestGetUserByPhoneRepo:
    async def test_ambiguity_refuses_fail_closed(self) -> None:
        session = MagicMock()
        result = MagicMock()
        result.scalars.return_value.all.return_value = [_user(), _user(id=uuid.uuid4())]
        session.execute = AsyncMock(return_value=result)
        assert await get_user_by_phone(session, PHONE) is None

    async def test_verified_match_resolves(self) -> None:
        user = _user()
        session = MagicMock()
        result = MagicMock()
        result.scalars.return_value.all.return_value = [user]
        session.execute = AsyncMock(return_value=result)
        assert await get_user_by_phone(session, PHONE) is user


class TestNotificationsEmailOtpChannel:
    async def test_email_leg_sends_via_notification_stack(self) -> None:
        channel = iv.NotificationsEmailOtpChannel()
        fake_session = AsyncMock()
        send = AsyncMock()
        with (
            patch("swx_core.services.notifications.provider_factory.send_via_email", send),
            patch("swx_core.database.db.async_session", MagicMock(return_value=fake_session)),
        ):
            await channel.send_verification_code(email=EMAIL, code="823941")

        notification = send.await_args.args[1]
        assert notification["recipient"] == EMAIL
        assert "823941" in notification["body"]


class TestIdentityGateThroughNotificationsChannel:
    async def test_both_mode_email_leg_via_notifications(self) -> None:
        user = _user(email=EMAIL, phone=PHONE)
        session = MagicMock()
        session.add = MagicMock()
        session.commit = AsyncMock()
        email_channel = iv.NotificationsEmailOtpChannel()
        phone_channel = MagicMock()
        phone_channel.send_verification_code = AsyncMock()
        iv.register_email_channel("swx-capture-email", email_channel)
        phv.register_phone_channel("swx-capture-phone", phone_channel)
        audit = _audit_mock()
        with (
            patch.object(settings, "SWX_IDENTITY_REQUIRED_VERIFICATIONS", "both"),
            patch.object(settings, "SWX_EMAIL_OTP_CHANNEL", "swx-capture-email-notifs"),
            patch.object(settings, "SWX_PHONE_VERIFICATION_CHANNEL", "swx-capture-phone"),
            patch.object(iv, "AuditLogger", return_value=audit),
        ):
            # re-register the email channel name to route via NotificationsEmailOtpChannel
            iv._EMAIL_CHANNELS["swx-capture-email-notifs"] = iv.NotificationsEmailOtpChannel()
            with patch("swx_core.database.db.async_session", MagicMock(return_value=AsyncMock())), \
                 patch("swx_core.services.notifications.provider_factory.send_via_email", AsyncMock()) as send:
                snapshot = await iv.request_identity_verification(session, user)

        assert snapshot["satisfied"] is False
        send.assert_awaited_once()
        notification = send.await_args.args[1]
        assert notification["recipient"] == EMAIL

        assert sorted(snapshot["delivered"]) == ["email", "phone"]


def _settings_mock() -> MagicMock: ...


from swx_core.config.settings import (  # noqa: E402
    settings,
)

