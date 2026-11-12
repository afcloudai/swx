# pyright: reportAny=false, reportExplicitAny=false, reportUnknownMemberType=false, reportUnknownArgumentType=false, reportMissingImports=false, reportUnusedCallResult=false, reportAttributeAccessIssue=false, reportArgumentType=false, reportCallIssue=false

"""
P0/P1/P4 conformance: PaystackProvider subscription lifecycle.

Regression anchors:
- P0: ``plan=`` MUST reach the /transaction/initialize payload (AFBiz's
  ensure_paystack_plan path raised AttributeError against the stale 2.32.0 wheel).
- P1: full Paystack-confirmed request contracts (paths + bodies).
- P4: MockBillingProvider implements the full Paystack-class surface.
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from swx_core.providers.billing_provider import MockBillingProvider
from swx_core.services.billing.providers.paystack_provider import PaystackProvider

pytestmark = pytest.mark.unit

CODE = "SUB_vsyqdmlzble3uii"
EMAIL_TOKEN = "d7gofp6yppn3qz7"
PLAN_CODE = "PLN_gx2wn530m0i3w3m"


def _provider() -> PaystackProvider:
    prov = PaystackProvider(secret_key="sk_test_x", public_key="pk_test_x")
    prov._request = AsyncMock(return_value={})  # type: ignore[method-assign]
    return prov


def _request_of(prov: PaystackProvider) -> AsyncMock:
    assert isinstance(prov._request, AsyncMock)
    return prov._request


class TestP0PlanAwareInitialize:
    async def test_plan_reaches_initialize_payload(self) -> None:
        """P0 regression: plan= is passed through VERBATIM to /transaction/initialize."""
        prov = _provider()
        await prov.initialize_payment(
            amount=50000, currency="NGN", email="merchant@example.com",
            reference="ref-1", callback_url="https://cb", plan=PLAN_CODE,
        )

        method, path, body = _request_of(prov).await_args.args
        assert (method, path) == ("POST", "/transaction/initialize")
        assert body is not None and body["plan"] == PLAN_CODE

    async def test_no_plan_drops_plan_key(self) -> None:
        prov = _provider()
        await prov.initialize_payment(
            amount=50000, currency="NGN", email="merchant@example.com",
            reference="ref-2", callback_url="https://cb",
        )

        _, _, body = _request_of(prov).await_args.args
        assert body is not None and "plan" not in body


class TestPlanMethods:
    async def test_fetch_plan_path(self) -> None:
        prov = _provider()
        await prov.fetch_plan(PLAN_CODE)

        method, path = _request_of(prov).await_args.args[:2]
        assert (method, path) == ("GET", f"/plan/{PLAN_CODE}")

    async def test_update_plan_always_sends_update_existing_false(self) -> None:
        """Paystack defaults update_existing_subscriptions to true — repricing a
        live fleet silently is exactly the failure this method exists to prevent."""
        prov = _provider()
        await prov.update_plan(PLAN_CODE, amount=45000)

        method, path, body = _request_of(prov).await_args.args
        assert (method, path) == ("PUT", f"/plan/{PLAN_CODE}")
        assert body is not None
        assert body["update_existing_subscriptions"] is False
        assert body["amount"] == 45000
        assert "name" not in body  # passthrough only sends provided params

    async def test_update_plan_full_passthrough(self) -> None:
        prov = _provider()
        await prov.update_plan(
            PLAN_CODE, name="Pro (renamed)", amount=45000, interval="monthly",
            currency="NGN", description="renamed", invoice_limit=10,
            send_invoices=False, send_sms=False,
        )

        _, _, body = _request_of(prov).await_args.args
        assert body is not None
        assert body == {
            "update_existing_subscriptions": False, "name": "Pro (renamed)",
            "amount": 45000, "interval": "monthly", "currency": "NGN",
            "description": "renamed", "invoice_limit": 10,
            "send_invoices": False, "send_sms": False,
        }


class TestSubscriptionMethods:
    async def test_create_subscription_contract(self) -> None:
        prov = _provider()
        await prov.create_subscription("CUS_xnxdt6s1zg1f4nx", PLAN_CODE)

        method, path, body = _request_of(prov).await_args.args
        assert (method, path) == ("POST", "/subscription")
        assert body is not None
        assert body == {"customer": "CUS_xnxdt6s1zg1f4nx", "plan": PLAN_CODE}

    async def test_create_subscription_full_params(self) -> None:
        prov = _provider()
        await prov.create_subscription(
            "CUS_xnxdt6s1zg1f4nx", PLAN_CODE,
            authorization="AUTH_6tmt288t0o", start_date="2017-05-16T00:30:13+01:00",
        )

        _, _, body = _request_of(prov).await_args.args
        assert body is not None
        assert body["authorization"] == "AUTH_6tmt288t0o"
        assert body["start_date"] == "2017-05-16T00:30:13+01:00"

    async def test_fetch_subscription_path(self) -> None:
        prov = _provider()
        await prov.fetch_subscription(CODE)

        assert _request_of(prov).await_args.args[:2] == ("GET", f"/subscription/{CODE}")

    async def test_list_subscriptions_numeric_id_filters(self) -> None:
        """Paystack's customer/plan filters take NUMERIC IDs, not codes."""
        prov = _provider()
        await prov.list_subscriptions(per_page=10, page=2, customer=1173, plan=28)

        _, path, query = _request_of(prov).await_args.args
        assert path == "/subscription"
        assert query is not None
        assert query["customer"] == 1173 and query["plan"] == 28
        assert query["perPage"] == 10 and query["page"] == 2

    async def test_enable_body_is_code_and_token_only(self) -> None:
        """The OpenAPI spec's stray required authorization field is a spec bug —
        do not send it."""
        prov = _provider()
        await prov.enable_subscription(CODE, EMAIL_TOKEN)

        method, path, body = _request_of(prov).await_args.args
        assert (method, path) == ("POST", "/subscription/enable")
        assert body is not None and body == {"code": CODE, "token": EMAIL_TOKEN}

    async def test_disable_body_is_code_and_token_only(self) -> None:
        prov = _provider()
        await prov.disable_subscription(CODE, EMAIL_TOKEN)

        method, path, body = _request_of(prov).await_args.args
        assert (method, path) == ("POST", "/subscription/disable")
        assert body is not None and body == {"code": CODE, "token": EMAIL_TOKEN}


class TestCustomerMethods:
    async def test_create_customer_contract(self) -> None:
        prov = _provider()
        await prov.create_customer(
            "merchant@example.com", first_name="Ayo", last_name="Ade", phone="+2348012345678",
        )

        method, path, body = _request_of(prov).await_args.args
        assert (method, path) == ("POST", "/customer")
        assert body is not None
        assert body["email"] == "merchant@example.com"
        assert body["first_name"] == "Ayo"

    async def test_fetch_customer_path(self) -> None:
        prov = _provider()
        await prov.fetch_customer("CUS_xnxdt6s1zg1f4nx")

        assert _request_of(prov).await_args.args[:2] == ("GET", "/customer/CUS_xnxdt6s1zg1f4nx")

    async def test_update_customer_has_no_email_field(self) -> None:
        """PUT /customer/:code has NO email field — email is immutable per
        Paystack; merchant rebinding must key on customer_code."""
        prov = _provider()
        await prov.update_customer(
            "CUS_xnxdt6s1zg1f4nx", first_name="Renamed", phone="+2348000000000",
            metadata={"plan_key": "pro_v1"},
        )

        method, path, body = _request_of(prov).await_args.args
        assert (method, path) == ("PUT", "/customer/CUS_xnxdt6s1zg1f4nx")
        assert body is not None
        assert "email" not in body
        assert body["first_name"] == "Renamed"
        assert body["metadata"] == {"plan_key": "pro_v1"}


class TestP4Parity:
    def test_paystack_implements_full_paystack_class_surface(self) -> None:
        surface = ["initialize_payment", "verify_payment", "refund",
                   "list_plans", "create_plan", "fetch_plan", "update_plan",
                   "fetch_subscription", "list_subscriptions", "create_subscription",
                   "enable_subscription", "disable_subscription",
                   "create_customer", "fetch_customer", "update_customer"]
        missing = [m for m in surface if not hasattr(PaystackProvider, m)]
        assert missing == []

    def test_mock_billing_provider_implements_same_surface(self) -> None:
        """Mock-vs-real shape drift is what broke AFBiz at the install boundary."""
        mock = MockBillingProvider()
        surface = ["initialize_payment", "verify_payment", "refund",
                   "list_plans", "create_plan", "fetch_plan", "update_plan",
                   "fetch_subscription", "list_subscriptions", "create_subscription",
                   "enable_subscription", "disable_subscription",
                   "create_customer", "fetch_customer", "get_customer", "update_customer",
                   "cancel_subscription", "get_subscription"]
        missing = [m for m in surface if not hasattr(mock, m)]
        assert missing == []

    async def test_mock_update_plan_honors_no_repricing_contract(self) -> None:
        mock = MockBillingProvider()
        result = await mock.update_plan("mock_plan_1", amount=45000)
        assert result["update_existing_subscriptions"] is False