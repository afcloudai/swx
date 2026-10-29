# pyright: reportMissingImports=false, reportAny=false, reportExplicitAny=false, reportUnknownMemberType=false, reportUnknownArgumentType=false, reportUnusedCallResult=false

"""
Phone verification service (SWX-IDM-001, D-1)
---------------------------------------------
Person-level phone verification behind the OIDC ``phone_verified`` claim:

- ``swx_users.phone`` (+ ``swx_users.phone_verified_at``) is the identity
  norm for phone-first registration; email is never involved.
- OTP codes REUSE the framework email-OTP machinery keyed ``phone:<user_id>``
  (bcrypt-hashed, attempt-limited, cooldown-guarded) — no second OTP framework.
- Delivery is pluggable: ``PhoneVerificationChannel`` implementations are
  registered with ``register_phone_channel`` and selected via the
  ``SWX_PHONE_VERIFICATION_CHANNEL`` setting. The shipped ``LoggingChannel``
  only logs the code (no transport is configured framework-side; the IdP app
  plugs its WhatsApp estate channel at bootstrap).
"""

import logging
import re
from typing import Any, Protocol

from sqlalchemy.ext.asyncio import AsyncSession

from swx_core.config.settings import settings
from swx_core.models.user import User
from swx_core.services.audit_logger import ActorType, AuditAction, AuditLogger, AuditOutcome
from swx_core.services.auth.email_otp_service import OtpInvalidError, generate_otp, verify_otp
from swx_core.utils.time import utc_now

logger = logging.getLogger("swx_core.oidc.phone_verification")

_E164_PATTERN = re.compile(r"\+[1-9]\d{6,14}")


class PhoneVerificationChannel(Protocol):
    """Delivery transport for verification codes (WhatsApp via the estate, SMS later)."""

    async def send_verification_code(self, *, phone: str, code: str, user_email: str | None = None) -> None: ...


class LoggingChannel:
    """Default channel: logs the code. Dev/testing convenience only."""

    async def send_verification_code(self, *, phone: str, code: str, user_email: str | None = None) -> None:
        logger.info("Phone verification code for %s: %s", phone, code)


_CHANNELS: dict[str, PhoneVerificationChannel] = {}


def register_phone_channel(name: str, channel: PhoneVerificationChannel) -> None:
    """Register a named delivery channel (idempotent last-write-wins)."""
    _CHANNELS[name] = channel


def resolve_phone_channel() -> PhoneVerificationChannel:
    """Channel selected by ``SWX_PHONE_VERIFICATION_CHANNEL``, defaulting to LoggingChannel."""
    configured = getattr(settings, "SWX_PHONE_VERIFICATION_CHANNEL", None)
    if configured:
        channel = _CHANNELS.get(configured)
        if channel is None:
            raise LookupError(f"Phone verification channel {configured!r} is not registered")
        return channel
    return _CHANNELS.setdefault("__default__", LoggingChannel())


def _otp_key(user_id: Any) -> str:
    return f"phone:{user_id}"


async def _audit(
    session: AsyncSession,
    action: str | AuditAction,
    *,
    outcome: AuditOutcome,
    context: dict[str, Any] | None,
    user: User,
) -> None:
    await AuditLogger(session).log_event(
        action=action,
        actor_type=ActorType.USER,
        actor_id=str(user.id),
        resource_type="phone_verification",
        resource_id=str(user.id),
        outcome=outcome,
        context=context or {},
    )


async def request_phone_verification(session: AsyncSession, user: User, phone: str) -> None:
    """Record ``phone`` on the user and deliver a fresh OTP via the configured channel."""
    if not _E164_PATTERN.fullmatch(phone):
        raise ValueError("phone must be in E.164 format (e.g. +2348012345678)")

    user.phone = phone
    # Claim integrity: a fresh verification request invalidates the previous
    # verified state — the new number is only claimed once re-confirmed via
    # its own OTP delivery, so a stale phone_verified flag can never attach
    # to an arbitrary (unverified) number.
    user.phone_verified_at = None
    session.add(user)
    await session.commit()

    code = await generate_otp(_otp_key(user.id))
    channel = resolve_phone_channel()
    await channel.send_verification_code(phone=phone, code=code, user_email=getattr(user, "email", None))

    await _audit(
        session,
        AuditAction.AUTH_PHONE_VERIFICATION_REQUESTED,
        outcome=AuditOutcome.SUCCESS,
        context={"phone": phone},
        user=user,
    )


async def confirm_phone_verification(session: AsyncSession, user: User, code: str) -> None:
    """Mark ``phone_verified_at`` when the delivered OTP matches; consumed on success."""
    verified = await verify_otp(_otp_key(user.id), str(code))
    if not verified:
        raise OtpInvalidError("Invalid or expired verification code")

    user.phone_verified_at = utc_now()
    session.add(user)
    await session.commit()

    await _audit(
        session,
        AuditAction.AUTH_PHONE_VERIFICATION_CONFIRMED,
        outcome=AuditOutcome.SUCCESS,
        context={"phone": getattr(user, "phone", None)},
        user=user,
    )