# pyright: reportMissingImports=false

"""
User phone-verification endpoints (SWX-IDM-001, D-1)
----------------------------------------------------
User-domain surface behind the OIDC ``phone_verified`` claim:

- ``POST /user/phone-verification/request`` — record the phone (E.164) and
  deliver an OTP via the registered channel
- ``POST /user/phone-verification/confirm`` — verify the OTP; flips
  ``phone_verified_at`` which gates the ``phone_verified`` claim
"""

from fastapi import APIRouter, HTTPException, Request
from sqlmodel import Field, SQLModel

from swx_core.auth.oidc_provider import phone_verification as phone_verification_service
from swx_core.auth.user.dependencies import UserDep
from swx_core.database.db import SessionDep
from swx_core.models.user import User
from swx_core.services.auth.email_otp_service import OtpInvalidError
from swx_core.utils.rate_limit import rate_limit_by_ip

router = APIRouter(prefix="/user/phone-verification", tags=["User - Phone Verification"])


class PhoneVerificationRequest(SQLModel):
    phone: str = Field(max_length=32)


class PhoneVerificationConfirmRequest(SQLModel):
    code: str = Field(min_length=4, max_length=10)


class PhoneVerificationStatus(SQLModel):
    phone: str | None = None
    phone_verified: bool = False


def _status(user: User) -> PhoneVerificationStatus:
    return PhoneVerificationStatus(
        phone=getattr(user, "phone", None),
        phone_verified=getattr(user, "phone_verified_at", None) is not None,
    )


@router.post("/request", response_model=PhoneVerificationStatus)
@rate_limit_by_ip(max_requests=3, window_seconds=60, action="phone_verification_request")
async def request_phone_verification(
    user: UserDep,
    body: PhoneVerificationRequest,
    request: Request,
    session: SessionDep,
) -> PhoneVerificationStatus:
    try:
        await phone_verification_service.request_phone_verification(session, user, body.phone)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return _status(user)


@router.post("/confirm", response_model=PhoneVerificationStatus)
@rate_limit_by_ip(max_requests=5, window_seconds=60, action="phone_verification_confirm")
async def confirm_phone_verification(
    user: UserDep,
    body: PhoneVerificationConfirmRequest,
    request: Request,
    session: SessionDep,
) -> PhoneVerificationStatus:
    try:
        await phone_verification_service.confirm_phone_verification(session, user, body.code)
    except OtpInvalidError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return _status(user)