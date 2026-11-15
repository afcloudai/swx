"""
Billing Service Provider.

Registers billing services including:
- Billing provider (Stripe)
- Subscription service
- Entitlement resolver
"""

from typing import Any

from swx_core.providers.base import ServiceProvider


class BillingServiceProvider(ServiceProvider):
    priority = 40

    def register(self) -> None:
        from swx_core.config.settings import settings

        if not settings.BILLING_ENABLED:
            return

        self.singleton("billing.provider", self._create_billing_provider)
        self.scoped("billing.subscription_service", self._create_subscription_service)
        self.scoped("billing.entitlement_resolver", self._create_entitlement_resolver)
        self.singleton("billing.feature_registry", self._create_feature_registry)
        self.alias("billing.provider", "BillingProvider")

    def boot(self) -> None:
        """Boot billing services."""
        from swx_core.container.container import get_container
        from swx_core.config.settings import settings
        from swx_core.middleware.logging_middleware import logger

        if not settings.BILLING_ENABLED:
            logger.debug("BillingServiceProvider: billing disabled, skipping boot")
            return

        container = get_container()

        if not container.bound("billing.feature_registry"):
            logger.debug("BillingServiceProvider: billing.feature_registry not bound, skipping boot")
            return

        logger.debug("BillingServiceProvider: resolving billing.feature_registry")
        registry = container.make("billing.feature_registry")
        self._register_default_features(registry)
        logger.info("BillingServiceProvider booted successfully")

    def _create_billing_provider(self, app):
        """
        Create billing provider based on configuration.

        Users can override this in swx_app/providers/app_provider.py:

            class AppServiceProvider(ServiceProvider):
                def register(self):
                    self.singleton("billing.provider", MyCustomBillingProvider)
        """
        from swx_core.config.settings import settings
        from swx_core.services.billing.stripe_provider import (
            StripeProvider,
            is_valid_stripe_api_key,
            is_valid_stripe_webhook_secret,
        )

        # Check for Stripe configuration
        stripe_api_key = getattr(settings, "STRIPE_API_KEY", None)
        stripe_webhook_secret = getattr(settings, "STRIPE_WEBHOOK_SECRET", None)

        if isinstance(stripe_api_key, str) and is_valid_stripe_api_key(stripe_api_key):
            return StripeProvider(
                api_key=stripe_api_key,
                webhook_secret=stripe_webhook_secret
                if isinstance(stripe_webhook_secret, str)
                and is_valid_stripe_webhook_secret(stripe_webhook_secret)
                else "",
            )

        # Return mock provider if no billing configured
        return MockBillingProvider()

    def _create_subscription_service(self, app):
        """Create subscription service."""
        from swx_core.services.billing.subscription_service import SubscriptionService

        return SubscriptionService

    def _create_entitlement_resolver(self, app):
        """Create entitlement resolver."""
        from swx_core.services.billing.entitlement_resolver import EntitlementResolver

        # Needs session
        if app.bound("db.session"):
            session = app.make("db.session")
            return EntitlementResolver(session)

        return EntitlementResolver

    def _create_feature_registry(self, app):
        """Create feature registry."""
        from swx_core.services.billing.feature_registry import FeatureRegistry

        return FeatureRegistry()

    def _register_default_features(self, registry) -> None:
        """Register default features if not already registered."""
        from swx_core.services.billing.feature_registry import FeatureDefinition, FeatureType

        core_features = [
            FeatureDefinition(
                key="api_requests",
                name="API Requests",
                feature_type=FeatureType.QUOTA,
                unit="requests",
                description="Monthly API request limit",
            ),
            FeatureDefinition(
                key="team_members",
                name="Team Members",
                feature_type=FeatureType.QUOTA,
                unit="members",
                description="Maximum team members",
            ),
            FeatureDefinition(
                key="advanced_analytics",
                name="Advanced Analytics",
                feature_type=FeatureType.BOOLEAN,
                description="Access to advanced analytics",
            ),
            FeatureDefinition(
                key="priority_support",
                name="Priority Support",
                feature_type=FeatureType.BOOLEAN,
                description="Priority support access",
            ),
        ]
        for feature in core_features:
            if feature.key not in registry._features:
                registry.register(feature)


class MockBillingProvider:
    """Mock billing provider for development/testing."""

    @property
    def name(self) -> str:
        return "mock"

    async def create_customer(
        self,
        email: str,
        name: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> str:
        return f"mock_customer_{email}"

    async def create_checkout_session(
        self,
        customer_id: str,
        price_id: str,
        success_url: str,
        cancel_url: str,
        metadata: dict[str, Any] | None = None,
    ) -> str:
        return "https://mock-checkout.example.com"

    async def create_subscription(
        self, customer_id: str, price_id: str, metadata: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        return {
            "id": f"mock_subscription_{customer_id}",
            "customer": customer_id,
            "price_id": price_id,
            "status": "active",
            "metadata": metadata or {},
        }

    async def cancel_subscription(
        self, subscription_id: str, at_period_end: bool = True
    ) -> bool:
        return True

    async def get_subscription(self, subscription_id: str) -> dict[str, Any]:
        return {
            "id": subscription_id,
            "status": "active",
            "current_period_start": 0,
            "current_period_end": 0,
        }

    async def get_customer(self, customer_id: str) -> dict[str, Any]:
        return {"id": customer_id, "email": "mock@example.com"}

    async def create_portal_session(self, customer_id: str, return_url: str) -> str:
        return "https://mock-portal.example.com"

    def verify_webhook(self, payload: bytes, signature: str) -> dict[str, Any]:
        return {"type": "mock.event", "data": {}}


    # ------------------------------------------------------------------
    # v2.33 parity: subscription-lifecycle surface (Paystack-class methods)
    # Mock-vs-real shape drift at the install boundary is what broke AFBiz —
    # the mock now implements the FULL surface its real counterpart offers.
    # ------------------------------------------------------------------

    async def list_plans(self, per_page: int = 50) -> list[dict[str, Any]]:
        return [{"id": "mock_plan_1", "name": "Mock Pro", "amount": 50000,
                 "interval": "monthly", "currency": "NGN"}]

    async def create_plan(self, name: str, amount_kobo: int, interval: str = "monthly") -> dict[str, Any]:
        return {"id": "mock_plan_new", "name": name, "amount": amount_kobo, "interval": interval}

    async def fetch_plan(self, plan_id_or_code: str) -> dict[str, Any]:
        return {"id": plan_id_or_code, "name": "Mock Pro", "amount": 50000,
                "interval": "monthly", "currency": "NGN"}

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
    ) -> dict[str, Any]:
        return {"id": plan_id_or_code, "status": True, "update_existing_subscriptions": False}

    async def fetch_subscription(self, subscription_id_or_code: str) -> dict[str, Any]:
        return {"id": subscription_id_or_code, "subscription_code": subscription_id_or_code,
                "status": "active", "email_token": "mock_email_token",
                "next_payment_date": None}

    async def list_subscriptions(
        self,
        per_page: int = 50,
        page: int = 1,
        customer: int | None = None,
        plan: int | None = None,
    ) -> list[dict[str, Any]]:
        return [{"subscription_code": "mock_sub_1", "status": "active",
                 "customer": customer, "plan": plan}]

    async def enable_subscription(self, code: str, email_token: str) -> dict[str, Any]:
        return {"code": code, "token": email_token, "enabled": True}

    async def disable_subscription(self, code: str, email_token: str) -> dict[str, Any]:
        return {"code": code, "token": email_token, "enabled": False}

    async def update_customer(
        self,
        customer_code: str,
        first_name: str | None = None,
        last_name: str | None = None,
        phone: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        return {"customer_code": customer_code, "status": True}

    async def initialize_payment(self, amount: int, currency: str, email: str,
                                 reference: str, callback_url: str, **kwargs: object) -> dict[str, Any]:
        return {"authorization_url": "https://mock-checkout.example.com", "reference": reference}

    def verify_webhook(self, payload: bytes, signature: str) -> dict[str, Any]:
        return {"type": "mock.event", "data": {}}

    async def verify_payment(self, reference: str) -> dict[str, Any]:
        return {"provider": "mock", "reference": reference, "status": "success", "paid": True}

    async def refund(self, reference: str, amount: int | None = None) -> dict[str, Any]:
        return {"provider": "mock", "reference": reference, "status": "refunded"}

    async def fetch_customer(self, customer_code_or_id: str) -> dict[str, Any]:
        return {"id": customer_code_or_id, "customer_code": customer_code_or_id}
