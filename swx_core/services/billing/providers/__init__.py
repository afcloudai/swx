from abc import ABC, abstractmethod

from swx_core.services.billing.billing_provider_base import BillingProvider


class LocalPaymentProvider(ABC):
    """
    Base provider surface.

    Core-mandated methods (initialize_payment, verify_payment, refund) are
    abstract; the following are PAYSTACK-CLASS methods (part of the
    subscription lifecycle in v2.33) — implement them when your provider
    supports managed subscriptions; local sweeps must never assume they exist:

    - list_plans / create_plan / fetch_plan / update_plan
    - fetch_subscription / list_subscriptions / create_subscription
    - enable_subscription / disable_subscription
    - create_customer / fetch_customer / update_customer
    """
    """Abstract base for local/African payment providers."""

    @abstractmethod
    async def initialize_payment(self, amount: int, currency: str, email: str, reference: str, callback_url: str, **kwargs: object) -> dict[str, object]:
        ...

    @abstractmethod
    async def verify_payment(self, reference: str) -> dict[str, object]:
        ...

    @abstractmethod
    async def refund(self, reference: str, amount: int | None = None) -> dict[str, object]:
        ...


__all__ = ["BillingProvider", "LocalPaymentProvider"]
