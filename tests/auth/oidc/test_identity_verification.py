# pyright: reportAny=false, reportExplicitAny=false, reportUnknownMemberType=false, reportUnknownArgumentType=false, reportMissingImports=false, reportUnusedCallResult=false, reportAttributeAccessIssue=false, reportArgumentType=false, reportCallIssue=false

"""
Unit tests for the identity-verification gate (v2.31): dual-OTP 'both' mode,
required-channel gate checks, and the authorize-side fail-closed hook.
"""

import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from swx_core.auth.oidc_provider import identity_verification as iv
from swx_core.auth.oidc_provider import grant_service as gv
from swx_core.auth.oidc_provider import repositories as oidc_repo
from swx_core.auth.oidc_provider import security as oidc_security
from swx_core.auth.oidc_provider.grant_service import OIDCAuthzError
from swx_core.auth.oidc_provider.models import OIDCClient
from swx_core.auth.oidc_provider import phone_verification as phv
from swx_core.config.settings import settings
from swx_core.services.audit_logger import AuditAction, AuditOutcome
from swx_core.services.auth.email_otp_service import OtpInvalidError

pytestmark = pytest.mark.unit

CLIENT_ID = "aabbccddeeff00112233445566778899"
PHONE = "+2348012345678"
EMAIL = "ayo@example.com"
VERIFIER = "v" * 45

from urllib.parse import parse_qs, urlsplit


def _audit_mock() -> MagicMock:
    mock = MagicMock()
    mock.log_event = AsyncMock()
    return mock


def _user(**overrides: object) -> MagicMock:
    data: dict[str, object] = {
        "id": uuid.uuid4(),
        "email": EMAIL,
        "email_verified_at": None,
        "phone": None,
        "phone_verified_at": None,
        "is_active": True,
    }
    data.update(overrides)
    return MagicMock(**data)


class CaptureChannel:
    def __init__(self) -> None:
        self.sent: list[dict] = []

    async def send_verification_code(self, **kwargs: object) -> None:
        self.sent.append(dict(kwargs))


def _request(url: str = "https://idp.example.com/api/oidc/authorize") -> MagicMock:
    request = MagicMock()
    request.headers = {}
    request.cookies = {}
    request.query_params = {}
    request.session = {}
    request.url = url
    request.base_url = "https://idp.example.com/"
    return request


def client_row(**overrides: object) -> OIDCClient:
    data: dict[str, object] = {
        "name": "RP Client",
        "client_id": CLIENT_ID,
        "redirect_uris": ["https://app.example.com/callback"],
        "grant_types": ["authorization_code", "refresh_token"],
        "scopes": ["openid", "profile", "phone", "offline_access"],
        "is_trusted": True,
    }
    data.update(overrides)
    return OIDCClient(**data)


def _valid_params(**overrides: str) -> dict[str, str]:
    from swx_core.auth.oidc_provider.security import s256_challenge

    params: dict[str, str] = {
        "client_id": CLIENT_ID,
        "redirect_uri": "https://app.example.com/callback",
        "response_type": "code",
        "scope": "openid profile phone offline_access",
        "state": "xyz",
        "code_challenge": s256_challenge(VERIFIER),
        "code_challenge_method": "S256",
    }
    params.update(overrides)
    return params


class TestVerificationState:
    def test_none_mode_satisfies_everything(self) -> None:
        with patch.object(settings, "SWX_IDENTITY_REQUIRED_VERIFICATIONS", "none"):
            state = iv.verification_state(_user())
        assert state["satisfied"] is True and state["missing"] == []

    def test_phone_mode_missing_phone(self) -> None:
        with patch.object(settings, "SWX_IDENTITY_REQUIRED_VERIFICATIONS", "phone"):
            state = iv.verification_state(_user())
        assert state["missing"] == ["phone"] and state["satisfied"] is False

    def test_email_mode_missing_email(self) -> None:
        with patch.object(settings, "SWX_IDENTITY_REQUIRED_VERIFICATIONS", "email"):
            state = iv.verification_state(_user())
        assert state["missing"] == ["email"]

    def test_both_mode_reports_both_missing(self) -> None:
        with patch.object(settings, "SWX_IDENTITY_REQUIRED_VERIFICATIONS", "both"):
            state = iv.verification_state(_user())
        assert state["missing"] == ["phone", "email"]

    def test_gate_error_none_when_satisfied(self) -> None:
        user = _user(email_verified_at=iv.utc_now(), phone_verified_at=iv.utc_now())
        with patch.object(settings, "SWX_IDENTITY_REQUIRED_VERIFICATIONS", "both"):
            assert iv.gate_error_for_user(user) is None


class TestDualDelivery:
    async def test_both_mode_sends_otp_to_both_channels(self) -> None:
        user = _user(phone=PHONE)
        email_channel = CaptureChannel()
        iv.register_email_channel("capture-email", email_channel)
        phone_channel = CaptureChannel()
        phv.register_phone_channel("capture-phone", phone_channel)
        session = MagicMock()
        session.add = MagicMock()
        session.commit = AsyncMock()
        audit = _audit_mock()
        with (
            patch.object(settings, "SWX_IDENTITY_REQUIRED_VERIFICATIONS", "both"),
            patch.object(settings, "SWX_EMAIL_OTP_CHANNEL", "capture-email"),
            patch.object(settings, "SWX_PHONE_VERIFICATION_CHANNEL", "capture-phone"),
            patch.object(iv, "AuditLogger", return_value=audit),
        ):
            snapshot = await iv.request_identity_verification(session, user)

        assert snapshot["delivered"] == ["phone", "email"]
        assert len(phone_channel.sent) == 1 and len(email_channel.sent) == 1
        assert email_channel.sent[0]["email"] == EMAIL
        assert audit.log_event.await_args.kwargs["action"] == AuditAction.AUTH_IDENTITY_VERIFICATION_REQUESTED

    async def test_refuses_without_phone_on_record(self) -> None:
        session = MagicMock()
        with (
            patch.object(settings, "SWX_IDENTITY_REQUIRED_VERIFICATIONS", "both"),
            pytest.raises(ValueError, match="phone-verification/request"),
        ):
            await iv.request_identity_verification(session, _user())

    async def test_refuses_email_leg_without_email(self) -> None:
        session = MagicMock()
        session.commit = AsyncMock()
        user = _user(email=None, phone=PHONE)
        with (
            patch.object(settings, "SWX_IDENTITY_REQUIRED_VERIFICATIONS", "both"),
            patch.object(settings, "SWX_EMAIL_OTP_CHANNEL", "capture-email"),
            pytest.raises(ValueError, match="no email"),
        ):
            await iv.request_identity_verification(session, user)


class TestConfirmCycle:
    async def test_both_channels_confirm_to_satisfied(self) -> None:
        user = _user(phone=PHONE)
        email_channel = CaptureChannel()
        iv.register_email_channel("capture-email", email_channel)
        phone_channel = CaptureChannel()
        phv.register_phone_channel("capture-phone", phone_channel)
        session = MagicMock()
        session.add = MagicMock()
        session.commit = AsyncMock()
        with (
            patch.object(settings, "SWX_IDENTITY_REQUIRED_VERIFICATIONS", "both"),
            patch.object(settings, "SWX_EMAIL_OTP_CHANNEL", "capture-email"),
            patch.object(settings, "SWX_PHONE_VERIFICATION_CHANNEL", "capture-phone"),
            patch.object(iv, "AuditLogger", return_value=_audit_mock()),
        ):
            snapshot = await iv.request_identity_verification(session, user)
            assert snapshot["satisfied"] is False
            _ = snapshot["delivered"]
            email_code = email_channel.sent[0]["code"]
            email_confirmed = await iv.confirm_identity_verification(session, user, "email", email_code)

        assert email_confirmed["email_verified"] is True
        assert email_confirmed["satisfied"] is False

        with (
            patch.object(settings, "SWX_IDENTITY_REQUIRED_VERIFICATIONS", "both"),
            patch.object(settings, "SWX_PHONE_VERIFICATION_CHANNEL", "capture-phone"),
            patch.object(iv, "AuditLogger", return_value=_audit_mock()),
        ):
            phone_confirmed = await iv.confirm_identity_verification(session, user, "phone", phone_channel.sent[0]["code"])

        assert phone_confirmed["phone_verified"] is True
        assert phone_confirmed["satisfied"] is True

    async def test_bad_channel_name_refused(self) -> None:
        with pytest.raises(ValueError, match="channel must be"):
            await iv.confirm_identity_verification(MagicMock(), _user(), "sms", "123456")

    async def test_wrong_email_code_refused(self) -> None:
        session = MagicMock()
        user = _user(email=EMAIL)
        with (
            patch.object(settings, "SWX_EMAIL_OTP_CHANNEL", None),
            pytest.raises(OtpInvalidError, match="Invalid or expired"),
        ):
            await iv.confirm_identity_verification(session, user, "email", "000000")


class TestAuthorizeGate:
    def _authorize_patches(self, user: object, payload: object = None) -> tuple:
        return (
            patch.object(oidc_repo, "get_client_by_public_id", AsyncMock(return_value=client_row())),
            patch.object(gv, "_resolve_optional_user", AsyncMock(return_value=(user, payload))),
            patch.object(gv, "AuditLogger", return_value=_audit_mock()),
        )

    async def test_unverified_identity_redirects_to_login(self) -> None:
        request = _request()
        patches = self._authorize_patches(_user(email=None), {"iat": 1760000000.0})
        with (
            patches[0],
            patches[1],
            patches[2],
            patch.object(settings, "SWX_IDENTITY_REQUIRED_VERIFICATIONS", "phone"),
            patch.object(oidc_repo, "create_grant_code", AsyncMock(return_value=MagicMock())) as create_code,
            patch.object(oidc_repo, "upsert_consent", AsyncMock()),
        ):
            response = await gv.authorize(MagicMock(), request, _valid_params(nonce="n-123"))

        location = str(response.headers["location"])
        assert location.startswith(settings.SWX_OIDC_LOGIN_URL)
        assert request.session["oidc_pending_grant"]["verification_required"] is True
        create_code.assert_not_awaited()

    async def test_prompt_none_refuses_closed(self) -> None:
        request = _request()
        patches = self._authorize_patches(_user(email=None), {"iat": 1760000000.0})
        with (
            patches[0],
            patches[1],
            patches[2],
            patch.object(settings, "SWX_IDENTITY_REQUIRED_VERIFICATIONS", "phone"),
            patch.object(oidc_repo, "create_grant_code", AsyncMock(return_value=MagicMock())),
        ):
            with pytest.raises(OIDCAuthzError, match="interaction_required"):
                await gv.authorize(MagicMock(), request, _valid_params(prompt="none", nonce="n-123"))

    async def test_satisfied_identity_issues_code(self) -> None:
        request = _request()
        verified_user = _user(phone=PHONE, phone_verified_at=iv.utc_now())
        patches = self._authorize_patches(verified_user, {"iat": 1760000000.0})
        with (
            patches[0],
            patches[1],
            patches[2],
            patch.object(settings, "SWX_IDENTITY_REQUIRED_VERIFICATIONS", "phone"),
            patch.object(oidc_repo, "create_grant_code", AsyncMock(return_value=MagicMock())) as create_code,
            patch.object(oidc_repo, "upsert_consent", AsyncMock()),
        ):
            response = await gv.authorize(MagicMock(), request, _valid_params(nonce="n-123"))

        assert _redirect_fields(response)["code"]
        create_code.assert_awaited_once()


def _redirect_fields(response: object) -> dict[str, str]:
    location = str(response.headers["location"])
    return {key: values[0] for key, values in parse_qs(urlsplit(location).query).items()}