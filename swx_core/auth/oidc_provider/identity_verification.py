# pyright: reportMissingImports=false, reportAny=false, reportExplicitAny=false, reportUnknownMemberType=false, reportUnknownArgumentType=false, reportUnusedCallResult=false

"""
Identity verification gate (SWX-IDM-001 v2.31)
----------------------------------------------
One identity row (``swx_users``), two verification channels:

- ``phone_verified_at`` — set via :mod:`phone_verification` (WhatsApp/SMS channel)
- ``email_verified_at`` — set here via the email-OTP leg

Required-verification modes (``SWX_IDENTITY_REQUIRED_VERIFICATIONS``):

- ``none``  — nothing required (phone-first default; adding nothing makes email required)
- ``phone`` — phone must be verified before the OIDC flow issues
- ``email`` — email must be verified
- ``both``  — bank-grade: ``request_identity_verification`` sends OTP to BOTH
  channels in one shot (dual delivery) and the gate refuses to issue until both
  confirmations are in (``interaction_required``)

Delivery is pluggable exactly like phone: register an ``EmailOtpChannel`` via
``register_email_channel`` and select with ``SWX_EMAIL_OTP_CHANNEL`` (default
logs the code).
"""

import logging
from typing import Any, Protocol

from sqlalchemy.ext.asyncio import AsyncSession

from swx_core.auth.oidc_provider import phone_verification as phv
from swx_core.models.user import User
from swx_core.config.settings import settings
from swx_core.services.audit_logger import ActorType, AuditAction, AuditLogger, AuditOutcome
from swx_core.services.auth.email_otp_service import OtpInvalidError, generate_otp, verify_otp
from swx_core.utils.time import utc_now

logger = logging.getLogger("swx_core.oidc.identity_verification")

_EMAIL_OTP_KEY = "email-verification"
_EMAIL_CHANNELS: dict[str, Any] = {}

REQUIRED_MODES = ("none", "phone", "email", "both")


class EmailOtpChannel(Protocol):
    async def send_verification_code(self, *, email: str, code: str) -> None: ...


class LoggingEmailOtpChannel:
    """Default email leg: logs the code (estate plugs SMTP/SendGrid at bootstrap)."""

    async def send_verification_code(self, *, email: str, code: str) -> None:
        logger.info("Email verification code for %s: %s", email, code)


def register_email_channel(name: str, channel: EmailOtpChannel) -> None:
    """Register a named email-OTP delivery channel (idempotent last-write-wins)."""
    _EMAIL_CHANNELS[name] = channel


def resolve_email_channel() -> EmailOtpChannel:
    configured = getattr(settings, "SWX_EMAIL_OTP_CHANNEL", None)
    if configured:
        channel = _EMAIL_CHANNELS.get(configured)
        if channel is None:
            raise LookupError(f"Email OTP channel {configured!r} is not registered")
        return channel
    return _EMAIL_CHANNELS.setdefault("__default__", LoggingEmailOtpChannel())


def _missing_channels(user: User) -> list[str]:
    required = getattr(settings, "SWX_IDENTITY_REQUIRED_VERIFICATIONS", "none")
    missing: list[str] = []
    if required in ("phone", "both") and getattr(user, "phone_verified_at", None) is None:
        missing.append("phone")
    if required in ("email", "both") and getattr(user, "email_verified_at", None) is None:
        missing.append("email")
    return missing


def verification_state(user: User) -> dict[str, Any]:
    """Verification snapshot used by gate checks and the /user endpoints."""
    missing = _missing_channels(user)
    return {
        "required": getattr(settings, "SWX_IDENTITY_REQUIRED_VERIFICATIONS", "none"),
        "email_verified": getattr(user, "email_verified_at", None) is not None,
        "phone_verified": getattr(user, "phone_verified_at", None) is not None,
        "satisfied": not missing,
        "missing": missing,
    }


def gate_error_for_user(user: User) -> tuple[str, str] | None:
    """OIDC authorize gate: ``(error, description)`` when the identity gate is unmet."""
    missing = _missing_channels(user)
    if not missing:
        return None
    return (
        "interaction_required",
        f"identity verification required: missing {', '.join(missing)}",
    )


async def _audit(
    session: AsyncSession, action: str | AuditAction, *, outcome: AuditOutcome, context: dict[str, Any], user: User
) -> None:
    await AuditLogger(session).log_event(
        action=action,
        actor_type=ActorType.USER,
        actor_id=str(user.id),
        resource_type="identity_verification",
        resource_id=str(user.id),
        outcome=outcome,
        context=context,
    )


async def request_identity_verification(session: AsyncSession, user: User, *, request: Any = None) -> dict[str, Any]:
    """Deliver OTP to every required channel in one shot (dual delivery for ``both``).

    Returns the verification snapshot with the delivered channels. Refuses with
    actionable guidance when a channel has nothing to deliver to yet (no phone
    recorded / no email).
    """
    required = getattr(settings, "SWX_IDENTITY_REQUIRED_VERIFICATIONS", "none")
    delivered: list[str] = []

    if required in ("phone", "both"):
        if not getattr(user, "phone", None):
            raise ValueError(
                "no phone on record: call POST /user/phone-verification/request first"
            )
        await phv.request_phone_verification(session, user, str(user.phone))
        delivered.append("phone")

    if required in ("email", "both"):
        email = getattr(user, "email", None)
        if not email:
            raise ValueError("no email on record for this account")
        code = await generate_otp(f"{_EMAIL_OTP_KEY}:{user.id}")
        channel = resolve_email_channel()
        await channel.send_verification_code(email=str(email), code=code)
        delivered.append("email")

    snapshot = verification_state(user)
    snapshot["delivered"] = delivered
    await _audit(
        session,
        AuditAction.AUTH_IDENTITY_VERIFICATION_REQUESTED,
        outcome=AuditOutcome.SUCCESS,
        context={"delivered": delivered},
        user=user,
    )
    return snapshot


async def confirm_identity_verification(
    session: AsyncSession, user: User, channel: str, code: str, *, request: Any = None
) -> dict[str, Any]:
    """Confirm one channel's OTP; sets that channel's verified timestamp."""
    if channel not in ("email", "phone"):
        raise ValueError("channel must be 'email' or 'phone'")

    if channel == "phone":
        await phv.confirm_phone_verification(session, user, str(code))
    else:
        verified = await verify_otp(f"{_EMAIL_OTP_KEY}:{user.id}", str(code))
        if not verified:
            raise OtpInvalidError("Invalid or expired verification code")
        user.email_verified_at = utc_now()
        session.add(user)
        await session.commit()

    snapshot = verification_state(user)
    await _audit(
        session,
        AuditAction.AUTH_IDENTITY_VERIFICATION_CONFIRMED,
        outcome=AuditOutcome.SUCCESS,
        context={"channel": channel, "satisfied": snapshot["satisfied"]},
        user=user,
    )
    return snapshot