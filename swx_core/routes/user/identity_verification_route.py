# pyright: reportMissingImports=false

"""
User identity-verification endpoints (SWX-IDM-001 v2.31)
--------------------------------------------------------
User-domain surface behind ``SWX_IDENTITY_REQUIRED_VERIFICATIONS``:

- ``POST /user/identity-verification/request`` — deliver OTP to every required
  channel in one shot (dual delivery for ``both``: email OTP + phone/WhatsApp OTP)
- ``POST /user/identity-verification/confirm`` — confirm one channel's OTP

The OIDC authorize flow refuses to issue until the required channels verify.
"""

from fastapi import APIRouter, HTTPException, Request
from sqlmodel import Field, SQLModel

from swx_core.auth.oidc_provider import identity_verification as identity_verification_service
from swx_core.auth.user.dependencies import UserDep
from swx_core.database.db import SessionDep
from swx_core.models.user import User
from swx_core.services.auth.email_otp_service import OtpInvalidError
from swx_core.utils.rate_limit import rate_limit_by_ip

router = APIRouter(prefix="/user/identity-verification", tags=["User - Identity Verification"])


class IdentityVerificationConfirmRequest(SQLModel):
    channel: str = Field(max_length=10)
    code: str = Field(min_length=4, max_length=10)


@router.post("/request")
@rate_limit_by_ip(max_requests=3, window_seconds=60, action="identity_verification_request")
async def request_identity_verification(
    user: UserDep,
    request: Request,
    session: SessionDep,
) -> dict:
    try:
        return await identity_verification_service.request_identity_verification(session, user)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/confirm")
@rate_limit_by_ip(max_requests=5, window_seconds=60, action="identity_verification_confirm")
async def confirm_identity_verification(
    user: UserDep,
    body: IdentityVerificationConfirmRequest,
    request: Request,
    session: SessionDep,
) -> dict:
    try:
        return await identity_verification_service.confirm_identity_verification(
            session, user, body.channel, body.code
        )
    except (ValueError, OtpInvalidError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc