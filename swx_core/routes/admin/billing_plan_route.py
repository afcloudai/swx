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
from swx_core.models.billing import Plan, PlanEntitlement, Feature
from swx_core.auth.admin.dependencies import AdminUserDep, get_current_admin_user
from swx_core.services.audit_logger import ActorType, AuditLogger, AuditOutcome

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
