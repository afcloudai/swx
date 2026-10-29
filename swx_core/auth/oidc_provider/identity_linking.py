# pyright: reportMissingImports=false, reportAny=false, reportExplicitAny=false, reportUnknownMemberType=false, reportUnknownArgumentType=false, reportUnusedCallResult=false

"""
External-identity linking (SWX-IDM-001, D-7)
--------------------------------------------
Consumer-side helpers that let products (Business Stage-1, platform console)
federate to the AFCloud IdP using the framework's existing OAuth-consumer
machinery:

- ``link_external_identity`` — bind an external IdP subject to a local user in
  ``swx_social_accounts`` (provider = IdP name, provider_id = idp_sub). The
  ticket requires matching by **verified phone**: the consumer's IdP claims
  must carry ``phone_verified=true`` or linking is refused (fail-closed).
- ``resolve_user_by_idp_sub`` — reverse lookup (login path): the local user
  owning an external subject, or ``None``.

``swx_social_accounts``' unique invariant on (provider, provider_id) from
v2.30.1 guarantees one external subject maps to one user — the helper enforces
it also at the application level (conflicts refuse).
"""

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from swx_core.models.social_account import SocialAccount
from swx_core.models.user import User
from swx_core.services.audit_logger import ActorType, AuditAction, AuditLogger, AuditOutcome
from swx_core.utils.time import utc_now


async def _audit(session: AsyncSession, *, context: dict, user: User) -> None:
    await AuditLogger(session).log_event(
        action=AuditAction.AUTH_IDENTITY_LINKED,
        actor_type=ActorType.USER,
        actor_id=str(user.id),
        resource_type="external_identity",
        resource_id=user.id,
        outcome=AuditOutcome.SUCCESS,
        context=context,
    )


async def link_external_identity(
    session: AsyncSession,
    user: User,
    idp_sub: str,
    idp: str,
    *,
    phone_verified_claim: bool,
) -> SocialAccount:
    """Bind ``idp:<idp_sub>`` to ``user``; refuses without a verified-phone claim.

    Idempotent for the same user (returns the existing link); subject conflicts
    (link owned by a different user) are refused. Refusals are audited.
    """
    try:
        return await _link_external_identity(session, user, idp_sub, idp, phone_verified_claim=phone_verified_claim)
    except ValueError as exc:
        await AuditLogger(session).log_event(
            action=AuditAction.AUTH_IDENTITY_LINKED,
            actor_type=ActorType.USER,
            actor_id=str(user.id),
            resource_type="external_identity",
            resource_id=str(user.id),
            outcome=AuditOutcome.FAILURE,
            context={"idp": idp, "idp_sub": idp_sub, "reason": str(exc)},
        )
        raise


async def _link_external_identity(
    session: AsyncSession,
    user: User,
    idp_sub: str,
    idp: str,
    *,
    phone_verified_claim: bool,
) -> SocialAccount:
    if not phone_verified_claim:
        raise ValueError("identity linking requires a verified phone claim from the IdP")

    stmt = select(SocialAccount).where(
        SocialAccount.provider == idp,
        SocialAccount.provider_id == idp_sub,
    )
    existing = (await session.execute(stmt)).scalar_one_or_none()
    if existing is not None:
        if existing.user_id != user.id:
            raise ValueError("external identity is already linked to another user")
        return existing

    account = SocialAccount(provider=idp, provider_id=idp_sub, user_id=user.id)
    session.add(account)
    await session.commit()
    await session.refresh(account)

    await _audit(session, context={"idp": idp, "idp_sub": idp_sub, "provider_email": account.provider_email}, user=user)
    return account


async def resolve_user_by_idp_sub(session: AsyncSession, idp_sub: str, idp: str) -> User | None:
    """Local user owning the ``idp:<idp_sub>`` external subject, or ``None``."""
    stmt = select(SocialAccount).where(
        SocialAccount.provider == idp,
        SocialAccount.provider_id == idp_sub,
    )
    account = (await session.execute(stmt)).scalar_one_or_none()
    if account is None:
        return None
    return await session.get(User, account.user_id)


async def provision_federated_identity(
    session: AsyncSession,
    *,
    idp: str,
    idp_sub: str,
    phone: str | None = None,
    full_name: str | None = None,
) -> User:
    """Stage-1 fallback: provision a local identity from verified IdP claims.

    Email stays None (optional forever — phone-first norm); the verified-phone
    claim seeds ``phone_verified_at`` so the identity links + matches by phone
    immediately. Platform LOGIN for email-less personas lands with the subject
    migration (D-10); until then consumers resolve the identity via its `sub`.
    """
    if not phone:
        raise ValueError("federated provisioning requires the phone claim")

    user = User(
        email=None,
        hashed_password=None,
        auth_provider=idp,
        provider_id=idp_sub,
        full_name=full_name,
        phone=phone,
        phone_verified_at=utc_now(),
    )
    session.add(user)
    await session.commit()
    await session.refresh(user)

    await link_external_identity(session, user, idp_sub, idp, phone_verified_claim=True)
    return user