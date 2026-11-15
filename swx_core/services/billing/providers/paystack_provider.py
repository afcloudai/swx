import logging
from typing import Protocol, cast

from fastapi import HTTPException
from typing_extensions import override

try:
    import httpx
except ImportError:
    httpx = None  # type: ignore[assignment]

from swx_core.services.billing.providers import LocalPaymentProvider


logger = logging.getLogger(__name__)


class _ResponseLike(Protocol):
    def raise_for_status(self) -> None:
        ...

    def json(self) -> dict[str, object]:
        ...


class PaystackProvider(LocalPaymentProvider):
    def __init__(self, secret_key: str, public_key: str, base_url: str = "https://api.paystack.co"):
        self.secret_key: str = secret_key
        self.public_key: str = public_key
        self.base_url: str = base_url.rstrip("/")

    async def _request(self, method: str, path: str, json: dict[str, object] | None = None) -> dict[str, object]:
        if httpx is None:
            raise RuntimeError("httpx is required for Paystack provider")
        try:
            async with httpx.AsyncClient(base_url=self.base_url, timeout=30.0) as client:
                response = cast(
                    _ResponseLike,
                    cast(
                        object,
                        await client.request(
                            method,
                            path,
                            json=json,
                            headers={
                                "Authorization": f"Bearer {self.secret_key}",
                                "Content-Type": "application/json",
                            },
                        ),
                    ),
                )
                response.raise_for_status()
                response_data = response.json()
        except (httpx.RequestError, httpx.HTTPStatusError) as exc:
            logger.exception("Paystack request failed for %s %s", method, path)
            raise HTTPException(status_code=503, detail="Paystack service unavailable") from exc
        return cast(dict[str, object], response_data.get("data", response_data))

    @override
    async def initialize_payment(self, amount: int, currency: str, email: str, reference: str, callback_url: str, **kwargs: object) -> dict[str, object]:
        request_payload = {
            "amount": amount,
            "currency": currency.upper(),
            "email": email,
            "reference": reference,
            "callback_url": callback_url,
            "metadata": kwargs.get("metadata", {}),
        }
        # THE PLAN-AWARE LAW (afbiz recovery): when a provider plan code is
        # supplied, Paystack runs the SUBSCRIPTION checkout (recurring billing
        # managed by the provider) and ignores `amount` — pass it through
        # verbatim and let the caller's amount tripwire reconcile.
        if kwargs.get("plan"):
            request_payload["plan"] = kwargs["plan"]
        data = await self._request("POST", "/transaction/initialize", request_payload)
        return {"provider": "paystack", "reference": reference, "authorization_url": data.get("authorization_url"), "access_code": data.get("access_code"), "raw": data}

    async def list_plans(self, per_page: int = 50) -> list[dict[str, object]]:
        data = await self._request("GET", f"/plan?perPage={per_page}")
        # _request already unwraps Paystack's envelope → list endpoints return a
        # LIST. Shape tolerance: accept the unwrapped list (authoritative), plus
        # a dict envelope defensively.
        items = data if isinstance(data, list) else ((data.get("data") if isinstance(data, dict) else None) or [])
        return [p for p in items if isinstance(p, dict)]

    async def create_plan(self, name: str, amount_kobo: int, interval: str = "monthly") -> dict[str, object]:
        data = await self._request("POST", "/plan", {
            "name": name, "amount": amount_kobo, "interval": interval,
        })
        return data

    async def disable_subscription(self, code: str, email_token: str) -> dict[str, object]:
        data = await self._request("POST", "/subscription/disable", {
            "code": code, "token": email_token,
        })
        return data

    @override
    async def verify_payment(self, reference: str) -> dict[str, object]:
        data = await self._request("GET", f"/transaction/verify/{reference}")
        return {"provider": "paystack", "reference": reference, "status": data.get("status"), "paid": data.get("status") == "success", "raw": data}

    @override
    async def refund(self, reference: str, amount: int | None = None) -> dict[str, object]:
        request_payload: dict[str, object] = {"transaction": reference}
        if amount is not None:
            request_payload["amount"] = amount
        data = await self._request("POST", "/refund", request_payload)
        return {"provider": "paystack", "reference": reference, "status": data.get("status"), "raw": data}

    # ------------------------------------------------------------------
    # Plans (v2.33 subscription lifecycle, SWX-IDM-001 P1)
    # ------------------------------------------------------------------

    async def fetch_plan(self, plan_id_or_code: str) -> dict[str, object]:
        """GET /plan/:id_or_code — validate a cached plan against the provider."""
        data = await self._request("GET", f"/plan/{plan_id_or_code}")
        return data

    async def update_plan(
        self,
        plan_id_or_code: str,
        name: str | None = None,
        amount: int | None = None,
        interval: str | None = None,
        currency: str | None = None,
        description: str | None = None,
        invoice_limit: int | None = None,
        send_invoices: bool | None = None,
        send_sms: bool | None = None,
    ) -> dict[str, object]:
        """PUT /plan/:id_or_code — full param passthrough.

        ``update_existing_subscriptions`` is ALWAYS sent as ``False``: Paystack
        defaults it to ``true``, which would silently reprice every existing
        subscriber. Repricing a live fleet must never be a side effect.
        """
        body: dict[str, object] = {"update_existing_subscriptions": False}
        if name is not None:
            body["name"] = name
        if amount is not None:
            body["amount"] = amount
        if interval is not None:
            body["interval"] = interval
        if currency is not None:
            body["currency"] = currency
        if description is not None:
            body["description"] = description
        if invoice_limit is not None:
            body["invoice_limit"] = invoice_limit
        if send_invoices is not None:
            body["send_invoices"] = send_invoices
        if send_sms is not None:
            body["send_sms"] = send_sms
        data = await self._request("PUT", f"/plan/{plan_id_or_code}", body)
        return data

    # ------------------------------------------------------------------
    # Subscriptions
    # ------------------------------------------------------------------

    async def fetch_subscription(self, subscription_id_or_code: str) -> dict[str, object]:
        """GET /subscription/:id_or_code — returns status, next_payment_date,
        email_token, and the expanded plan/customer (reconciliation + the
        agent's get_next_billing_date)."""
        data = await self._request("GET", f"/subscription/{subscription_id_or_code}")
        return data

    async def list_subscriptions(
        self,
        per_page: int = 50,
        page: int = 1,
        customer: int | None = None,
        plan: int | None = None,
    ) -> list[dict[str, object]]:
        """GET /subscription — Paystack's customer/plan filters take NUMERIC IDs
        (not codes); resolve stored codes to IDs before calling."""
        query: dict[str, object] = {"perPage": per_page, "page": page}
        if customer is not None:
            query["customer"] = customer
        if plan is not None:
            query["plan"] = plan
        data = await self._request("GET", "/subscription", query)
        items = data if isinstance(data, list) else ((data.get("data") if isinstance(data, dict) else None) or [])
        return [p for p in items if isinstance(p, dict)]

    async def create_subscription(
        self,
        customer: str,
        plan: str,
        authorization: str | None = None,
        start_date: str | None = None,
    ) -> dict[str, object]:
        """POST /subscription — the existing-authorization path (Free→paid with
        a reusable card on file; no first charge documented at creation).

        ``customer`` accepts email or customer code; ``plan`` is the plan code.
        Response carries subscription_code, email_token, next_payment_date.
        """
        body: dict[str, object] = {"customer": customer, "plan": plan}
        if authorization is not None:
            body["authorization"] = authorization
        if start_date is not None:
            body["start_date"] = start_date
        data = await self._request("POST", "/subscription", body)
        return data

    async def enable_subscription(self, code: str, email_token: str) -> dict[str, object]:
        """POST /subscription/enable — cancel-then-resubscribe mirror of disable.

        Body is code + token ONLY: the OpenAPI spec's stray required
        ``authorization`` field is a spec bug (confirmed against the enable
        sample) — do not send it.
        """
        data = await self._request("POST", "/subscription/enable", {
            "code": code, "token": email_token,
        })
        return data

    # ------------------------------------------------------------------
    # Customers (v2.33 customer lifecycle)
    # ------------------------------------------------------------------

    async def create_customer(
        self,
        email: str,
        first_name: str | None = None,
        last_name: str | None = None,
        phone: str | None = None,
        metadata: dict[str, object] | None = None,
    ) -> dict[str, object]:
        """POST /customer — returns customer_code (the join key)."""
        body: dict[str, object] = {"email": email}
        if first_name is not None:
            body["first_name"] = first_name
        if last_name is not None:
            body["last_name"] = last_name
        if phone is not None:
            body["phone"] = phone
        if metadata is not None:
            body["metadata"] = metadata
        data = await self._request("POST", "/customer", body)
        return data

    async def fetch_customer(self, customer_code_or_id: str) -> dict[str, object]:
        """GET /customer/:code_or_id."""
        data = await self._request("GET", f"/customer/{customer_code_or_id}")
        return data

    async def update_customer(
        self,
        customer_code: str,
        first_name: str | None = None,
        last_name: str | None = None,
        phone: str | None = None,
        metadata: dict[str, object] | None = None,
    ) -> dict[str, object]:
        """PUT /customer/:code — email is IMMUTABLE per Paystack docs; it is
        deliberately absent from the update body. Merchant rebinding keys on
        customer_code, never email."""
        body: dict[str, object] = {}
        if first_name is not None:
            body["first_name"] = first_name
        if last_name is not None:
            body["last_name"] = last_name
        if phone is not None:
            body["phone"] = phone
        if metadata is not None:
            body["metadata"] = metadata
        data = await self._request("PUT", f"/customer/{customer_code}", body)
        return data
