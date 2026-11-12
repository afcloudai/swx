"""
Plan Management Routes
----------------------
Admin-only APIs for managing plans and entitlements.
"""

from typing import Any, List
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select

from swx_core.database.db import SessionDep
from swx_core.models.billing import Plan, PlanEntitlement, Feature, Subscription
from swx_core.auth.admin.dependencies import AdminUserDep, get_current_admin_user
from swx_core.services.audit_logger import ActorType, AuditLogger, AuditOutcome
from swx_core.services.billing.providers.paystack_provider import PaystackProvider
from swx_core.services.billing.subscription_service import SubscriptionService
from swx_core.utils.rate_limit import rate_limit_by_ip

router = APIRouter(
    prefix="/admin/billing/plan",
    tags=["admin-billing"],
    dependencies=[Depends(get_current_admin_user)]
)

@router.get("/", response_model=List[Plan])
async def list_plans(session: SessionDep):
    """List all billing plans."""
    stmt = select(Plan)
    result = await session.execute(stmt)
    return list(result.scalars().all())

@router.post("/", response_model=Plan, status_code=status.HTTP_201_CREATED)
async def create_plan(plan: Plan, request: Request, session: SessionDep, _admin: AdminUserDep):
    """Create a new billing plan."""
    session.add(plan)
    await session.commit()
    await session.refresh(plan)

    # P3/18: admin plan writes were hitting the DB audit-free — every entitlement
    # grant is billing-sensitive, so the existing audit machinery now covers it.
    await AuditLogger(session).log_event(
        action="admin.billing_plan_created",
        actor_type=ActorType.ADMIN,
        actor_id=str(_admin.id) if hasattr(_admin, "id") else None,
        resource_type="billing_plan",
        resource_id=str(plan.id),
        outcome=AuditOutcome.SUCCESS,
        context={"key": plan.key, "name": plan.name, "amount": plan.amount,
                 "currency": plan.currency, "interval": str(plan.billing_interval)},
        request=request,
    )
    return plan

@router.post("/{plan_id}/entitlement/{feature_id}")
async def assign_entitlement(
    plan_id: UUID,
    feature_id: UUID,
    value: str,
    request: Request,
    session: SessionDep,
    _admin: AdminUserDep,
):
    """Assign an entitlement to a plan."""
    entitlement = PlanEntitlement(
        plan_id=plan_id,
        feature_id=feature_id,
        value=value
    )
    session.add(entitlement)
    await session.commit()
    await session.refresh(entitlement)

    await AuditLogger(session).log_event(
        action="admin.billing_entitlement_assigned",
        actor_type=ActorType.ADMIN,
        actor_id=str(_admin.id) if hasattr(_admin, "id") else None,
        resource_type="billing_plan_entitlement",
        resource_id=str(entitlement.id),
        outcome=AuditOutcome.SUCCESS,
        context={"plan_id": str(plan_id), "feature_id": str(feature_id), "value": value},
        request=request,
    )
    return {"message": "Entitlement assigned"}


@router.post("/paystack/transactions/{reference}/verify", response_model=dict[str, object])
@rate_limit_by_ip(max_requests=10, window_seconds=60, action="paystack_verify")
async def admin_paystack_verify_transaction(
    reference: str,
    request: Request,
    session: SessionDep,
    _admin: AdminUserDep,
) -> dict[str, object]:
    """P2/14: pull-verify a transaction by reference — missed-webhook recovery."""
    from swx_core.config.settings import settings

    provider = PaystackProvider(
        secret_key=settings.PAYSTACK_SECRET_KEY,
        public_key=settings.PAYSTACK_PUBLIC_KEY,
    )
    result = await provider.verify_payment(reference)

    await AuditLogger(session).log_event(
        action="admin.paystack_transaction_verified",
        actor_type=ActorType.ADMIN,
        actor_id=str(_admin.id) if hasattr(_admin, "id") else None,
        resource_type="paystack_transaction",
        resource_id=reference,
        outcome=AuditOutcome.SUCCESS,
        context={"paid": result.get("paid"), "email": None},
        request=request,
    )
    return result


@router.post("/paystack/subscriptions/{code}/refresh", response_model=Subscription)
@rate_limit_by_ip(max_requests=10, window_seconds=60, action="paystack_refresh")
async def admin_paystack_refresh_subscription(
    code: str,
    request: Request,
    session: SessionDep,
    _admin: AdminUserDep,
) -> Subscription:
    """P2/14: refresh a Paystack subscription from the provider and sync state locally."""
    from swx_core.config.settings import settings

    provider = PaystackProvider(
        secret_key=settings.PAYSTACK_SECRET_KEY,
        public_key=settings.PAYSTACK_PUBLIC_KEY,
    )
    prov_status = await provider.fetch_subscription(code)
    service = SubscriptionService(session)
    sub_id = await service.sync_paystack_subscription(prov_status)
    await AuditLogger(session).log_event(
        action="admin.paystack_subscription_refreshed",
        actor_type=ActorType.ADMIN,
        actor_id=str(_admin.id) if hasattr(_admin, "id") else None,
        resource_type="billing_subscription",
        resource_id=str(sub_id) if sub_id else code,
        outcome=AuditOutcome.SUCCESS,
        context={"subscription_code": code, "synced": sub_id is not None},
        request=request,
    )
    if sub_id is None:
        raise HTTPException(status_code=404, detail="No local subscription matched this Paystack code")
    refreshed = await service.get_subscription_by_id(sub_id)
    return refreshed  # type: ignore[return-value]
