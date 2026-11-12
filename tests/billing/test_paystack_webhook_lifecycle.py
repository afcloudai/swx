# pyright: reportAny=false, reportExplicitAny=false, reportUnknownMemberType=false, reportUnknownArgumentType=false, reportMissingImports=false, reportUnusedCallResult=false, reportAttributeAccessIssue=false, reportArgumentType=false, reportCallIssue=false

"""
P2 conformance: Paystack webhook lifecycle — event spellings, durable
idempotency, customer-code user resolution, and SubscriptionService sync.
"""

import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from swx_core.webhooks.paystack_webhook import (
    PaystackWebhookHandler,
    _SUPPORTED_EVENTS,
)

pytestmark = pytest.mark.unit

SECRET = "sk_test_webhook"
EVENT_ID = "evt_recurring_001"


def _signed(payload: bytes) -> str:
    import hashlib
    import hmac

    return hmac.new(SECRET.encode(), payload, hashlib.sha512).hexdigest()


def _payload(event: str, data: dict) -> bytes:
    import json

    return json.dumps({"event": event, "data": data}).encode()


def _handler(redis_client=None, session_factory=None) -> PaystackWebhookHandler:
    return PaystackWebhookHandler(secret_key=SECRET, redis_client=redis_client, session_factory=session_factory)


class TestEventSpellings:
    """P2/10: literal spellings validated here — merging in TEST confirms them."""

    def test_recurring_lifecycle_events_registered(self) -> None:
        assert {
            "charge.success",
            "subscription.create", "subscription.not_renew", "subscription.disable",
            "invoice.create", "invoice.update", "invoice.payment_failed",
        } <= _SUPPORTED_EVENTS

    async def test_unsupported_event_ignored(self) -> None:
        handler = _handler()
        payload = _payload("subscription.gibberish", {"reference": "r1"})
        result = await handler.handle(payload, _signed(payload))
        assert result.status == "ignored"


class TestDurableIdempotency:
    async def test_duplicate_event_via_durable_table(self) -> None:
        """P2/11: check_and_record (durable table + Redis fast-path) — no Redis-only replay loss."""
        session_factory = MagicMock()
        fake_session = AsyncMock()
        fake_session.__aenter__ = AsyncMock(return_value=fake_session)
        fake_session.__aexit__ = AsyncMock(return_value=False)
        session_factory.return_value = fake_session
        with (
            patch("swx_core.services.webhook_idempotency_service.check_and_record", AsyncMock(return_value=False)) as check,
            patch("swx_core.database.db.AsyncSessionLocal", MagicMock(return_value=fake_session)) as _local,
        ):
            _ = _local
            handler = _handler(session_factory=session_factory)
            payload = _payload("charge.success", {
                "reference": "ORD-1", "amount": 100000, "customer": {"email": "a@b.c"}, "status": "success",
            })
            result = await handler.handle(payload, _signed(payload))

        assert result.status == "duplicate"
        check.assert_awaited_once()
        assert check.await_args.args[1] == "paystack"  # provider bound


class TestCustomerCodeResolution:
    async def test_user_resolved_by_customer_code_first(self) -> None:
        """P2/13: customer_code is the join key; email only as fallback."""
        session_factory = MagicMock()
        fake_session = AsyncMock()
        session_factory.return_value = fake_session

        owner = MagicMock(id=uuid.uuid4())
        account = MagicMock(owner_id=owner.id)
        by_email = AsyncMock()
        handler = _handler(session_factory=session_factory)
        with (
            patch("swx_core.services.webhook_idempotency_service.check_and_record", AsyncMock(return_value=True)),
            patch("swx_core.webhooks.paystack_webhook.get_billing_account_by_paystack_customer",
                  AsyncMock(return_value=account)),
            patch("swx_core.webhooks.paystack_webhook.get_user_by_id", AsyncMock(return_value=owner)),
            patch("swx_core.webhooks.paystack_webhook.find_user_by_email", by_email),
            patch("swx_core.webhooks.paystack_webhook.apply_payment", AsyncMock()),
            patch("swx_core.webhooks.paystack_webhook.kobo_to_nano", lambda kobo: kobo * 1_000_000),
            patch("swx_core.webhooks.paystack_webhook.parse_reference_prefix",
                  lambda ref: ("app", "pro_v1")),
        ):
            payload = _payload("charge.success", {
                "reference": "ORD-42", "amount": 100000,
                "customer": {
                    "customer_code": "CUS_paystack_code_1",  # join key, NOT the email
                    "email": "whatever@x",
                },
                "status": "success",
            })
            result = await handler.handle(payload, _signed(payload))

        assert result.status == "success"
        by_email.assert_not_awaited()  # customer_code resolved first — email NOT the join key
