# pyright: reportMissingImports=false

"""
Account-recovery endpoints (SWX-IDM-001, D-9)
---------------------------------------------
Phone-OTP password recovery — access domain (pre-authentication):

- ``POST /auth/recovery/request``  {"phone"} — sends a recovery OTP when (and
  only when) the account's phone is VERIFIED; identical response otherwise
  (no account enumeration)
- ``POST /auth/recovery/confirm``  {"phone","code","new_password"} — resets the
  password and revokes every active session + OIDC refresh family

The email recovery path is unchanged and stays available for email identities.
"""

from fastapi import APIRouter, HTTPException, Request
from sqlmodel import Field, SQLModel

from swx_core.auth.oidc_provider import recovery as recovery_service
from swx_core.database.db import SessionDep
from swx_core.services.auth.email_otp_service import OtpInvalidError
from swx_core.utils.rate_limit import rate_limit_by_ip

router = APIRouter(prefix="/auth/recovery", tags=["Auth - Account Recovery"])


class RecoveryRequest(SQLModel):
    phone: str = Field(max_length=32)


class RecoveryConfirmRequest(SQLModel):
    phone: str = Field(max_length=32)
    code: str = Field(min_length=4, max_length=10)
    new_password: str = Field(min_length=8, max_length=40)


@router.post("/request")
@rate_limit_by_ip(max_requests=3, window_seconds=60, action="recovery_request")
async def request_recovery(
    body: RecoveryRequest,
    request: Request,
    session: SessionDep,
) -> dict[str, str]:
    try:
        return await recovery_service.request_phone_recovery(session, body.phone)
    except LookupError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/confirm")
@rate_limit_by_ip(max_requests=5, window_seconds=60, action="recovery_confirm")
async def confirm_recovery(
    body: RecoveryConfirmRequest,
    request: Request,
    session: SessionDep,
) -> dict[str, str]:
    try:
        return await recovery_service.confirm_phone_recovery(
            session, phone=body.phone, code=body.code, new_password=body.new_password
        )
    except OtpInvalidError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc