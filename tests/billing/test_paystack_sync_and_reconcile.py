import uuid
# pyright: reportAny=false, reportExplicitAny=false, reportUnknownMemberType=false, reportUnknownArgumentType=false, reportMissingImports=false, reportUnusedCallResult=false, reportAttributeAccessIssue=false, reportArgumentType=false, reportCallIssue=false

"""
P2/12 + P2/14 conformance: webhook→sync wiring and admin reconciliation.
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from swx_core.webhooks.paystack_webhook import (
    _handle_subscription_event,
    _provider_status_for,
    _SUBSCRIPTION_SYNC_EVENTS,
)

pytestmark = pytest.mark.unit

CODE = "SUB_lifecycle_1"


async def _sync_mock() -> AsyncMock:
    return AsyncMock(return_value=uuid.uuid4())


def _fake_service_returning(sub_id: uuid.UUID) -> MagicMock:
    svc = MagicMock()
    svc.sync_paystack_subscription = AsyncMock(return_value=sub_id)
    svc.get_subscription_by_id = AsyncMock(return_value=MagicMock(id=sub_id))
    return svc


class TestWebhookSyncWiring:
    def test_subscription_events_route_to_sync(self) -> None:
        """P2/12: recurring lifecycle events drive SubscriptionService.sync."""
        assert _SUBSCRIPTION_SYNC_EVENTS == {
            "subscription.create", "subscription.not_renew",
            "subscription.disable", "invoice.payment_failed",
        }

    def test_status_mapping(self) -> None:
        assert _provider_status_for("subscription.create", {}) == "active"
        assert _provider_status_for("subscription.not_renew", {}) == "non-renewing"
        assert _provider_status_for("invoice.payment_failed", {}) == "attention"
        # documented terminal ambiguity: disable with payload status 'complete'
        assert _provider_status_for("subscription.disable", {"status": "complete"}) == "completed"
        assert _provider_status_for("subscription.disable", {"status": "cancelled"}) == "cancelled"

    async def test_not_renew_event_syncs_service(self) -> None:
        sub_id = uuid.uuid4()
        payload_data = {
            "subscription_code": CODE, "status": "non-renewing",
            "customer": {"customer_code": "CUS_1", "email": "a@b.c"},
        }
        with (
            patch("swx_core.webhooks.paystack_webhook.SubscriptionService") as svc_cls,
            patch("swx_core.services.audit_logger.AuditLogger") as audit_logger,
        ):
            svc_cls.return_value = _fake_service_returning(sub_id)
            result = await _handle_subscription_event(
                session_factory=MagicMock(), event_type="subscription.not_renewing", data=payload_data,
            ) if False else await _handle_subscription_event(
                session_factory=MagicMock(), event_type="subscription.not_renew", data=payload_data,
            )

        assert result.status == "success"
        prov_status = svc_cls.return_value.sync_paystack_subscription.await_args.args[0]
        assert prov_status == {"subscription_code": CODE, "status": "non-renewing", "next_payment_date": None}
        _ = audit_logger

    async def test_disable_terminal_ambiguity_preserved(self) -> None:
        sub_id = uuid.uuid4()
        payload_data = {
            "subscription_code": CODE, "status": "complete",
            "customer": {"customer_code": "CUS_1"},
        }
        with (
            patch("swx_core.webhooks.paystack_webhook.SubscriptionService") as svc_cls,
            patch("swx_core.services.audit_logger.AuditLogger"),
        ):
            svc_cls.return_value = _fake_service_returning(sub_id)
            await _handle_subscription_event(
                session_factory=MagicMock(), event_type="subscription.disable", data=payload_data,
            )

        prov_status = svc_cls.return_value.sync_paystack_subscription.await_args.args[0]
        assert prov_status["status"] == "completed"  # 'complete' → completed; 'cancelled' → cancelled

    async def test_missing_subscription_code_ignored(self) -> None:
        result = await _handle_subscription_event(
            session_factory=MagicMock(), event_type="subscription.create", data={},
        )
        assert result.status == "ignored"



def _audit_mock() -> MagicMock:
    mock = MagicMock()
    mock.log_event = AsyncMock()
    return mock


class TestAdminReconciliation:
    """P2/14: missed-webhook recovery — admin-guarded, pull-verify, sync, audited."""

    def _no_redis(self) -> None:
        """Endpoints carry the rate-limit decorator applied at import time
        (`rate_limit_by_ip`); point the module limiter at a no-redis instance
        so decorated calls never dial redis in tests."""
        import importlib
        rl = importlib.import_module("swx_core.utils.rate_limit")

        limiter = rl.RateLimiter(redis_url=None)
        rl._rate_limiter = limiter

    async def _run_verify(self, reference: str = "ORD-recovery-1") -> tuple[object, MagicMock]:
        from swx_core.config.settings import settings

        admin = MagicMock(id=uuid.uuid4())
        audit_logger = _audit_mock()
        request = MagicMock()
        session = MagicMock()
        self._no_redis()

        with (
            patch.object(settings, "PAYSTACK_SECRET_KEY", "sk_test_x"),
            patch.object(settings, "PAYSTACK_PUBLIC_KEY", "pk_test_x"),
            patch("swx_core.routes.admin.billing_plan_route.PaystackProvider") as provider_cls,
            patch("swx_core.routes.admin.billing_plan_route.AuditLogger", return_value=audit_logger),
        ):
            provider_cls.return_value.verify_payment = AsyncMock(
                return_value={"provider": "paystack", "reference": reference, "paid": True}
            )
            from swx_core.routes.admin.billing_plan_route import (
                admin_paystack_verify_transaction,
            )

            result = await admin_paystack_verify_transaction(reference, request, session, admin)
        return result, audit_logger

    async def _run_refresh(self, code: str = CODE) -> tuple[object, MagicMock]:
        from swx_core.config.settings import settings

        admin = MagicMock(id=uuid.uuid4())
        audit_logger = _audit_mock()
        request = MagicMock()
        session = MagicMock()
        session.commit = AsyncMock()
        sub_id = uuid.uuid4()
        service = MagicMock()
        service.sync_paystack_subscription = AsyncMock(return_value=sub_id)
        service.get_subscription_by_id = AsyncMock(return_value=MagicMock(id=sub_id))
        self._no_redis()

        with (
            patch.object(settings, "PAYSTACK_SECRET_KEY", "sk_test_x"),
            patch.object(settings, "PAYSTACK_PUBLIC_KEY", "pk_test_x"),
            patch("swx_core.routes.admin.billing_plan_route.PaystackProvider") as provider_cls,
            patch("swx_core.routes.admin.billing_plan_route.SubscriptionService", return_value=service),
            patch("swx_core.routes.admin.billing_plan_route.AuditLogger", return_value=audit_logger),
        ):
            provider_cls.return_value.fetch_subscription = AsyncMock(
                return_value={"subscription_code": code, "status": "active",
                              "next_payment_date": "2026-12-01"}
            )
            from swx_core.routes.admin.billing_plan_route import (
                admin_paystack_refresh_subscription,
            )

            result = await admin_paystack_refresh_subscription(code, request, session, admin)
        return result, audit_logger

    async def test_verify_returns_provider_result_and_audits(self) -> None:
        result, audit_logger = await self._run_verify()

        assert result["paid"] is True
        assert audit_logger.log_event.await_args.kwargs["action"] == "admin.paystack_transaction_verified"
        assert audit_logger.log_event.await_args.kwargs["actor_id"] is not None

    async def test_refresh_pulls_provider_syncs_and_audits(self) -> None:
        result, audit_logger = await self._run_refresh()

        assert result.id is not None
        actions = [c.kwargs["action"] for c in audit_logger.log_event.await_args_list]
        assert "admin.paystack_subscription_refreshed" in actions
        assert audit_logger.log_event.await_args.kwargs["context"]["synced"] is True
