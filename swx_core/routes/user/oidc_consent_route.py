# pyright: reportMissingImports=false

"""
User OIDC-consent surface (SWX-IDM-001 v2.31)
---------------------------------------------
"Manage consents" for the identity owner:

- ``GET /user/oidc-consents`` — every granted consent of the current user
- ``DELETE /user/oidc-consents/{client_id}`` — revoke; the next authorize run
  narrows to the un-revoked/registered scope (audit: ``auth.consent_revoked``)
"""

from fastapi import APIRouter, HTTPException, Request

from swx_core.auth.oidc_provider import repositories as oidc_repo
from swx_core.auth.oidc_provider.models import OIDCConsentPublic
from swx_core.auth.user.dependencies import UserDep
from swx_core.database.db import SessionDep
from swx_core.models.user import User
from swx_core.services.audit_logger import ActorType, AuditAction, AuditLogger, AuditOutcome
from swx_core.utils.rate_limit import rate_limit_by_ip

router = APIRouter(prefix="/user/oidc-consents", tags=["User - OIDC Consents"])


@router.get("/", response_model=list[OIDCConsentPublic])
async def list_my_consents(user: UserDep, session: SessionDep) -> list[OIDCConsentPublic]:
    consents = await oidc_repo.list_consents_for_user(session, user.id)
    return [OIDCConsentPublic.model_validate(consent) for consent in consents]


@router.delete("/{client_id}", response_model=OIDCConsentPublic)
@rate_limit_by_ip(max_requests=10, window_seconds=60, action="oidc_consent_revoke")
async def revoke_my_consent(
    user: UserDep,
    client_id: str,
    request: Request,
    session: SessionDep,
) -> OIDCConsentPublic:
    consent = await oidc_repo.revoke_consent(session, user.id, client_id)
    if consent is None:
        raise HTTPException(status_code=404, detail="No consent for this client")
    if consent.revoked_at is not None:
        await AuditLogger(session).log_event(
            action=AuditAction.AUTH_CONSENT_REVOKED,
            actor_type=ActorType.USER,
            actor_id=str(user.id),
            resource_type="oidc_client",
            resource_id=client_id,
            outcome=AuditOutcome.SUCCESS,
            context={"client_id": client_id},
            request=request,
        )
    return OIDCConsentPublic.model_validate(consent)