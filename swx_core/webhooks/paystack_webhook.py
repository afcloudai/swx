"""
Paystack Webhook Handler.

Implements webhook handling for Paystack payment events with:
- HMAC-SHA512 signature verification
- Kobo → nano conversion
- Reference prefix routing (plan-{key} → subscription, pack-{key} → wallet credit)
- Idempotent wallet credit (by Paystack reference)
- Redis fast-path idempotency (falls back to ledger idempotency)

Shared apply logic lives in ``payment_confirmation_service`` so both
the webhook and the /confirm endpoint use the same subscription/wallet
creation code without double-processing.
"""

import hashlib
import hmac
import json
from dataclasses import dataclass
from typing import Any, Optional

from fastapi import APIRouter, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from swx_core.config.settings import settings
from swx_core.database.db import AsyncSessionLocal
from swx_core.middleware.logging_middleware import logger
from swx_core.models.billing import BillingAccountType
from swx_core.repositories.user_repository import get_user_by_id
from swx_core.services.billing.payment_confirmation_service import (
    apply_payment,
    find_user_by_email,
    parse_reference_prefix,
)
from swx_core.repositories.billing_repository import (
    get_billing_account_by_paystack_customer,
)
from swx_core.services.billing.subscription_service import SubscriptionService
from swx_core.utils.currency import kobo_to_nano

router = APIRouter(prefix="/webhooks", tags=["Webhooks"])




@dataclass
class PaystackWebhookResult:
    status: str
    reference: str | None = None
    event_type: str | None = None
    message: str | None = None


def _verify_signature(payload: bytes, signature: str, secret: str) -> bool:
    expected = hmac.new(secret.encode(), payload, hashlib.sha512).hexdigest()
    return hmac.compare_digest(expected, signature)


def _extract_payload_fields(data: dict[str, Any]) -> tuple[str, int, str, str, str, str] | None:
    """Returns (reference, amount_kobo, email, currency, status, customer_code)."""
    reference = data.get("reference")
    amount_kobo = data.get("amount")
    customer = data.get("customer")
    email = customer.get("email") if isinstance(customer, dict) else None
    # Paystack customer object in charge events carries `customer_code`; string
    # customer fields (subscription payloads) carry the code directly.
    customer_code = (
        customer.get("customer_code") if isinstance(customer, dict)
        else customer if isinstance(customer, str)
        else None
    )
    currency = data.get("currency", settings.DEFAULT_BASE_CURRENCY)
    status_value = data.get("status", "")

    if not isinstance(reference, str) or not isinstance(amount_kobo, int):
        return None
    if not isinstance(email, str) or not email:
        return None

    return reference, amount_kobo, email, currency, status_value, customer_code or ""


_SUPPORTED_EVENTS = {
    "charge.success",
    # Recurring lifecycle (v2.33) — literal spellings from Paystack's docs;
    # validated by test_paystack_webhook_events.py::test_event_spellings
    "subscription.create",
    "subscription.not_renew",     # cancel not to renew on next payment date
    "subscription.disable",       # cancelled OR completed (payload status tells which)
    "invoice.create",
    "invoice.update",
    "invoice.payment_failed",
}


_SUBSCRIPTION_SYNC_EVENTS = {
    "subscription.create", "subscription.not_renew", "subscription.disable",
    "invoice.payment_failed",
}


def _provider_status_for(event_type: str, data: dict[str, Any]) -> str | None:
    """Map Paystack event payloads to the sync layer's provider status lexicon.

    Note the documented terminal ambiguity: subscription.disable carries payload
    status 'complete' (all cycles billed) or 'cancelled' — BOTH map to
    'completed'/'cancelled' on our side; the sync layer records the difference."""
    if event_type == "subscription.create":
        return "active"
    if event_type == "subscription.not_renew":
        return "non-renewing"
    if event_type == "invoice.payment_failed":
        return "attention"
    if event_type == "subscription.disable":
        payload_status = str(data.get("status", "")).casefold()
        return "completed" if payload_status in ("complete", "completed") else "cancelled"
    return None


async def _handle_subscription_event(
    *,
    session_factory,  # type: ignore[no-untyped-def]
    event_type: str,
    data: dict[str, Any],
) -> PaystackWebhookResult:
    subscription_code = (
        data.get("subscription_code")
        or data.get("code")
        or (data.get("subscription", {}).get("subscription_code") if isinstance(data.get("subscription"), dict) else None)
    )
    if not isinstance(subscription_code, str) or not subscription_code:
        logger.warning("Paystack webhook: %s payload has no subscription_code", event_type)
        return PaystackWebhookResult(status="ignored", event_type=event_type, message="No subscription code")

    async with AsyncSessionLocal() as session:
        service = SubscriptionService(session)
        synced = await service.sync_paystack_subscription({
            "subscription_code": subscription_code,
            "status": _provider_status_for(event_type, data) or "",
            "next_payment_date": data.get("next_payment_date"),
        })
        if synced is None:
            return PaystackWebhookResult(
                status="ignored", event_type=event_type,
                message=f"No local subscription for {subscription_code}",
            )
    return PaystackWebhookResult(
        status="success", event_type=event_type,
        message=f"Synced subscription {subscription_code}",
    )



class PaystackWebhookHandler:
    def __init__(self, secret_key: str, redis_client=None, session_factory=None):
        self.secret_key = secret_key
        self.redis = redis_client
        # Durable idempotency (v2.33): Redis is a fast-path cache only — the
        # swx_inbound_webhook_delivery table survives restarts (P2/11).
        self.session_factory = session_factory

    async def handle(self, payload: bytes, signature: str) -> PaystackWebhookResult:
        if not signature:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Missing signature",
            )

        if not _verify_signature(payload, signature, self.secret_key):
            logger.warning("Paystack webhook signature verification failed")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid signature",
            )

        try:
            event = json.loads(payload)
        except json.JSONDecodeError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid payload",
            )

        event_type = event.get("event", "")
        data = event.get("data", {})
        if not isinstance(data, dict):
            return PaystackWebhookResult(status="ignored", event_type=event_type, message="No data object")

        # P2/12: recurring lifecycle events drive SubscriptionService sync —
        # charge.success keeps the one-off purchase path below.
        if event_type in _SUBSCRIPTION_SYNC_EVENTS:
            return await _handle_subscription_event(session_factory=self.session_factory,
                                                    event_type=event_type, data=data)

        if event_type not in _SUPPORTED_EVENTS:
            logger.info("Paystack webhook: unsupported event %s", event_type)
            return PaystackWebhookResult(status="ignored", event_type=event_type, message="Event not supported")

        fields = _extract_payload_fields(data)
        if fields is None:
            logger.warning("Paystack webhook: could not extract fields from data")
            return PaystackWebhookResult(status="error", event_type=event_type, message="Missing required fields")

        reference, amount_kobo, email, currency, paystack_status, customer_code = fields

        if paystack_status != "success":
            logger.info("Paystack webhook: reference %s status %s, skipping", reference, paystack_status)
            return PaystackWebhookResult(
                status="ignored", reference=reference, event_type=event_type,
                message=f"Payment status {paystack_status}",
            )

        event_id = str(event.get("id", reference))
        if self.session_factory is not None:
            async with self.session_factory() as db_session:
                from swx_core.services.webhook_idempotency_service import (
                    check_and_record,
                )

                is_new = await check_and_record(
                    db_session, "paystack", event_id, payload, redis_client=self.redis,
                )
                if not is_new:
                    logger.info("Paystack webhook: duplicate event %s", event_id)
                    return PaystackWebhookResult(
                        status="duplicate", reference=reference, event_type=event_type,
                        message="Already processed",
                    )
        elif self.redis is not None:
            dedup_key = f"webhook:paystack:idempotency:{reference}"
            if await self.redis.exists(dedup_key):
                logger.info("Paystack webhook: duplicate reference %s", reference)
                return PaystackWebhookResult(
                    status="duplicate", reference=reference, event_type=event_type,
                    message="Already processed",
                )

        amount_nano = kobo_to_nano(amount_kobo)
        purchase_type, item_key = parse_reference_prefix(reference)

        try:
            async with AsyncSessionLocal() as session:
                # P2/13: resolve by customer_code first (email is mutable in our
                # books and immutable in theirs — never the join key).
                user = None
                if customer_code:
                    account = await get_billing_account_by_paystack_customer(
                        session, customer_code
                    )
                    if account is not None:
                        user = await get_user_by_id(session=session, user_id=account.owner_id)
                if user is None and email:
                    user = await find_user_by_email(session, email)  # FALLBACK ONLY
                if user is None:
                    logger.warning("Paystack webhook: no user for customer_code %s or email %s",
                                   customer_code, email)
                    return PaystackWebhookResult(
                        status="error", reference=reference, event_type=event_type,
                        message="User not found",
                    )

                await apply_payment(
                    session, user.id, reference, amount_nano, currency,
                    purchase_type, item_key,
                )
                await session.commit()
        except Exception:
            logger.exception("Paystack webhook: failed to process reference %s", reference)
            return PaystackWebhookResult(
                status="error", reference=reference, event_type=event_type,
                message="Processing failed",
            )

        if self.redis is not None:
            await self.redis.setex(
                f"webhook:paystack:idempotency:{reference}", settings.WEBHOOK_IDEMPOTENCY_TTL, event_type
            )

        return PaystackWebhookResult(
            status="success", reference=reference, event_type=event_type
        )


def _resolve_webhook_secret() -> str | None:
    """Resolve the Paystack webhook secret, falling back to the API secret key.

    Handles ${ENV_VAR} placeholders that pydantic-settings returns when the
    env var is not set — the placeholder is truthy but not a real secret.
    """
    webhook_secret = settings.PAYSTACK_WEBHOOK_SECRET
    if webhook_secret and not webhook_secret.startswith("${"):
        return webhook_secret

    api_secret = settings.PAYSTACK_SECRET_KEY
    if api_secret and not api_secret.startswith("${"):
        return api_secret

    return None


_handler: Optional[PaystackWebhookHandler] = None


def get_paystack_webhook_handler() -> Optional[PaystackWebhookHandler]:
    global _handler

    secret = _resolve_webhook_secret()
    if secret is None:
        return None

    if _handler is None:
        redis_client = None
        try:
            from swx_core.container.container import get_container

            container = get_container()
            if container.bound("redis.client"):
                redis_client = container.make("redis.client")
        except Exception:
            logger.debug("Redis client unavailable, webhook idempotency will use ledger fallback")

        _handler = PaystackWebhookHandler(secret_key=secret, redis_client=redis_client)

    return _handler


@router.post("/paystack")
async def paystack_webhook(request: Request):
    handler = get_paystack_webhook_handler()
    if handler is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Paystack webhook secret is not configured",
        )

    payload = await request.body()
    signature = request.headers.get("x-paystack-signature", "")

    try:
        result = await handler.handle(payload, signature)
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("Paystack webhook handling error: %s", exc, exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal error",
        )

    if result.status == "duplicate":
        return {"status": "success", "message": "Duplicate event"}

    if result.status == "ignored":
        return {"status": "success", "message": result.message}

    if result.status == "error":
        return {"status": "success", "message": "Processing failed"}

    return {"status": "success", "reference": result.reference}


@router.get("/paystack/health")
async def paystack_webhook_health():
    return {"status": "healthy", "endpoint": "/webhooks/paystack"}
