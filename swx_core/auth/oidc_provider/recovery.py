# pyright: reportMissingImports=false, reportAny=false, reportExplicitAny=false, reportUnknownMemberType=false, reportUnknownArgumentType=false, reportUnusedCallResult=false

"""
Phone-OTP account recovery (SWX-IDM-001, D-9)
---------------------------------------------
Self-service password recovery for phone-first identities (no email involved):

- ``request_phone_recovery`` — records a recovery OTP ONLY for accounts whose
  phone VERIFIED (``swx_users.phone_verified_at`` set); unknown/unverified
  phones get the SAME silent response (no account enumeration).
- ``confirm_phone_recovery`` — the OTP plus a new password: the password is
  reset, and EVERY active credential of that identity dies (platform refresh
  tokens via ``revoke_all_tokens`` + all OIDC refresh families) — a stolen
  password gains nothing.

OTP codes reuse the framework email-OTP machinery keyed ``recovery:<user_id>``
(bcrypt-hashed, attempt-limited, cooldown-guarded); delivered via the
registered ``PhoneVerificationChannel`` (WhatsApp estate channel).
"""

from typing import Any

from fastapi import Request
from sqlalchemy.ext.asyncio import AsyncSession

from swx_core.auth.oidc_provider import repositories as oidc_repo
from swx_core.auth.oidc_provider.phone_verification import resolve_phone_channel
from swx_core.config.settings import settings
from swx_core.models.user import User
from swx_core.security.password_security import get_password_hash
from swx_core.services.audit_logger import ActorType, AuditAction, AuditLogger, AuditOutcome
from swx_core.services.auth.email_otp_service import OtpInvalidError, generate_otp, verify_otp
from swx_core.utils.time import utc_now

_RECOVERY_OTP_KEY = "recovery"


async def _audit(
    session: AsyncSession, action: str | AuditAction, *, outcome: AuditOutcome, context: dict[str, Any], user: User
) -> None:
    await AuditLogger(session).log_event(
        action=action,
        actor_type=ActorType.USER,
        actor_id=str(user.id),
        resource_type="account_recovery",
        resource_id=str(user.id),
        outcome=outcome,
        context=context,
    )


async def request_phone_recovery(session: AsyncSession, phone: str) -> dict[str, str]:
    """Issue a recovery OTP to a VERIFIED phone — enumera-safe by construction."""
    user = await oidc_repo.find_user_by_verified_phone(session, phone.strip())
    if user is not None:
        code = await generate_otp(f"{_RECOVERY_OTP_KEY}:{user.id}")
        channel = resolve_phone_channel()
        await channel.send_verification_code(phone=phone, code=code, user_email=None)
        await _audit(
            session,
            AuditAction.AUTH_PHONE_RECOVERY_REQUESTED,
            outcome=AuditOutcome.SUCCESS,
            context={"phone": phone},
            user=user,
        )
    return {"status": "processed"}


async def confirm_phone_recovery(
    session: AsyncSession,
    *,
    phone: str,
    code: str,
    new_password: str,
) -> dict[str, str]:
    """Verify the recovery OTP; reset the password; kill every active credential."""
    user = await oidc_repo.find_user_by_verified_phone(session, phone.strip())
    if user is not None:
        verified = await verify_otp(f"{_RECOVERY_OTP_KEY}:{user.id}", str(code))
    else:
        verified = False

    if not verified:
        if user is not None:
            await _audit(
                session,
                AuditAction.AUTH_PHONE_RECOVERY_COMPLETED,
                outcome=AuditOutcome.FAILURE,
                context={"phone": phone, "reason": "invalid_or_expired_code"},
                user=user,
            )
        raise OtpInvalidError("Invalid or expired recovery code")

    user.hashed_password = await get_password_hash(new_password)
    session.add(user)
    await session.commit()

    from swx_core.security.refresh_token_service import revoke_all_tokens

    await revoke_all_tokens(session, str(user.email))
    families = await oidc_repo.revoke_families_for_user(session, user.id)

    await _audit(
        session,
        AuditAction.AUTH_PHONE_RECOVERY_COMPLETED,
        outcome=AuditOutcome.SUCCESS,
        context={"phone": phone, "families_revoked": families},
        user=user,
    )
    return {"status": "reset"}