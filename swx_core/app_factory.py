"""
SwX Application Factory
------------------------
Create a fully-configured FastAPI application with one call.

``create_swx_app()`` replaces the 370-line ``main.py`` with a declarative
entry point.  It wires up:

* Deterministic bootstrap (providers, routes, hooks, listeners)
* Structured exception handlers (production-safe)
* Ordered middleware stack (security-correct)
* Lifecycle service manager (start in order, stop in reverse)
* Background scheduler (declarative recurring tasks)
* Production configuration validation

Usage (thin application entry point)::

    from swx_core import create_swx_app

    app = create_swx_app(
        title="QiroPrint API",
        app_name="qiro_app",
    )

    # Register application-specific behaviour:
    from qiro_app.providers import AppServiceProvider
    from swx_core.bootstrap import bootstrap_app

    container = bootstrap_app(app)

Applications that need the legacy ``main.py`` behaviour can continue
to import it directly — this factory is the recommended path forward.
"""

from __future__ import annotations

import asyncio
import inspect
from contextlib import asynccontextmanager
from typing import Any, Callable, Optional

from fastapi import FastAPI

from swx_core.config.settings import settings
from swx_core.exceptions.handlers import register_exception_handlers
from swx_core.lifecycle import GracefulShutdown, LifecycleManager, LifecycleService
from swx_core.middleware.logging_middleware import logger
from swx_core.middleware.stack import apply_middleware_stack
from swx_core.router import router


# ---------------------------------------------------------------------------
# Lifecycle service base for async-task services
# ---------------------------------------------------------------------------


class _AsyncTaskService(LifecycleService):
    """Base for lifecycle services that manage a single ``asyncio.Task``.

    Subclasses set ``name`` and implement ``start()`` to create
    ``self._task``.  The shared ``stop()`` cancels and awaits the task.
    """

    _task: Any = None

    async def stop(self) -> None:
        if self._task and not self._task.done():
            self._task.cancel()
            try:
                await self._task
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Built-in lifecycle services
# ---------------------------------------------------------------------------


class JobRunnerService(LifecycleService):
    """Start and stop the background job runner."""

    name = "job_runner"

    async def start(self) -> None:
        from swx_core.services.job import start_job_runner
        await start_job_runner()

    async def stop(self) -> None:
        from swx_core.services.job import stop_job_runner
        try:
            await stop_job_runner()
        except Exception:
            logger.exception("lifecycle.stop_failed service=%s", self.name)


class AuditQueueService(LifecycleService):
    """Start and stop the audit event queue drain worker."""

    name = "audit_queue"

    async def start(self) -> None:
        from swx_core.services.audit.audit_event_queue import audit_queue
        await audit_queue.start()

    async def stop(self) -> None:
        from swx_core.services.audit.audit_event_queue import audit_queue
        await audit_queue.stop()


class RedisBridgeService(LifecycleService):
    """Start and stop the Redis event bridge for cross-worker events."""

    name = "redis_event_bridge"

    def __init__(self) -> None:
        self._bridge: Any = None

    async def start(self) -> None:
        if not settings.REDIS_ENABLED or not settings.EVENT_BRIDGE_ENABLED:
            logger.info("lifecycle.skip service=%s (disabled)", self.name)
            return

        from swx_core.container.container import get_container
        from swx_core.events.dispatcher import event_bus

        container = get_container()
        bridge = None

        if container.bound("event_bridge"):
            try:
                bridge = container.make("event_bridge")
            except Exception as exc:
                logger.warning("Failed to create event bridge from container: %s", exc)

        if bridge is None:
            try:
                redis_client = None
                if container.bound("redis.client"):
                    redis_client = container.make("redis.client")

                if redis_client is not None:
                    from swx_core.events.redis_bridge import RedisEventBridge

                    bridge = RedisEventBridge(
                        event_bus=event_bus,
                        redis_client=redis_client,
                        channel_prefix=settings.EVENT_BRIDGE_CHANNEL_PREFIX,
                        app_name=RedisEventBridge.default_app_name(settings.PROJECT_NAME),
                    )
                    bridge.patch_dispatch()
            except Exception as exc:
                logger.warning("Could not create event bridge directly: %s", exc)

        if bridge is not None:
            await bridge.start()
            self._bridge = bridge
            logger.info("lifecycle.started service=%s", self.name)
        else:
            logger.debug("Redis event bridge skipped (unavailable or disabled)")

    async def stop(self) -> None:
        if self._bridge is not None:
            await self._bridge.stop()
            self._bridge = None


class _SIEMFlushService(_AsyncTaskService):
    name = "siem_batch_flush"

    async def start(self) -> None:
        import asyncio
        from swx_core.services.compliance.siem_service import siem_batch_loop
        self._task = asyncio.create_task(siem_batch_loop())
        logger.info("lifecycle.started service=%s interval=%ds", self.name, getattr(settings, "SIEM_BATCH_INTERVAL", 60))


class _APIKeyLifecycleService(_AsyncTaskService):
    name = "api_key_lifecycle"

    async def start(self) -> None:
        import asyncio
        from swx_core.services.compliance.api_key_lifecycle_service import api_key_lifecycle_loop
        self._task = asyncio.create_task(api_key_lifecycle_loop())
        logger.info("lifecycle.started service=%s", self.name)


class _SessionCleanupService(_AsyncTaskService):
    name = "session_idle_cleanup"

    async def start(self) -> None:
        import asyncio
        from swx_core.services.auth.session_service import session_idle_cleanup_loop
        self._task = asyncio.create_task(session_idle_cleanup_loop())
        logger.info("lifecycle.started service=%s", self.name)


class _SSEManagerService(LifecycleService):
    """Start and stop the SSE connection manager and its Redis bridge."""

    name = "sse_manager"

    def __init__(self) -> None:
        self._bridge: Any = None

    async def start(self) -> None:
        from swx_core.sse.manager import SSEManager

        manager = SSEManager.get_instance()
        if manager is not None:
            await manager.start()

        if not settings.REDIS_ENABLED or not settings.SSE_BRIDGE_ENABLED:
            return

        from swx_core.container.container import get_container
        from swx_core.sse.redis_bridge import SSERedisBridge

        container = get_container()
        redis_client = None
        if container.bound("redis.client"):
            try:
                redis_client = container.make("redis.client")
            except Exception as exc:
                logger.warning("sse.redis_bridge.redis_unavailable %s", exc)
                return

        if redis_client is not None and manager is not None:
            bridge = SSERedisBridge(
                sse_manager=manager,
                redis_client=redis_client,
                channel_prefix=settings.SSE_BRIDGE_CHANNEL_PREFIX,
            )
            await bridge.start()
            manager._redis_bridge = bridge
            self._bridge = bridge
            logger.info("sse.redis_bridge.wired")

    async def stop(self) -> None:
        if self._bridge is not None:
            await self._bridge.stop()
            self._bridge = None

        from swx_core.sse.manager import SSEManager
        manager = SSEManager.get_instance()
        if manager is not None:
            manager._redis_bridge = None
            await manager.stop()


class _WSManagerService(LifecycleService):
    """Start and stop the WebSocket connection manager and its Redis bridge."""

    name = "ws_manager"

    def __init__(self) -> None:
        self._bridge: Any = None

    async def start(self) -> None:
        from swx_core.websocket.manager import ConnectionManager

        manager = ConnectionManager.get_instance()
        if manager is not None:
            await manager.start()

        if not settings.REDIS_ENABLED or not settings.WS_BRIDGE_ENABLED:
            return

        from swx_core.container.container import get_container
        from swx_core.websocket.redis_bridge import WSRedisBridge

        container = get_container()
        redis_client = None
        if container.bound("redis.client"):
            try:
                redis_client = container.make("redis.client")
            except Exception as exc:
                logger.warning("ws.redis_bridge.redis_unavailable %s", exc)
                return

        if redis_client is not None and manager is not None:
            bridge = WSRedisBridge(
                ws_manager=manager,
                redis_client=redis_client,
                channel_prefix=settings.WS_BRIDGE_CHANNEL_PREFIX,
            )
            await bridge.start()
            manager._redis_bridge = bridge
            self._bridge = bridge
            logger.info("ws.redis_bridge.wired")

    async def stop(self) -> None:
        if self._bridge is not None:
            await self._bridge.stop()
            self._bridge = None

        from swx_core.websocket.manager import ConnectionManager
        manager = ConnectionManager.get_instance()
        if manager is not None:
            manager._redis_bridge = None
            await manager.stop()


class _CacheRefreshService(_AsyncTaskService):
    name = "cache_refresh"

    async def start(self) -> None:
        import asyncio
        from swx_core.background_task import refresh_translation_cache
        self._task = asyncio.create_task(refresh_translation_cache())
        logger.info("lifecycle.started service=%s", self.name)


# ---------------------------------------------------------------------------
# Lifespan builder
# ---------------------------------------------------------------------------


def _build_lifespan(
    lifecycle: LifecycleManager,
    on_startup: Optional[Callable[[FastAPI], Any]] = None,
    graceful_shutdown: Optional[GracefulShutdown] = None,
) -> Any:
    """Build an async context manager that runs lifecycle services."""

    @asynccontextmanager
    async def lifespan(app: FastAPI):  # type: ignore[misc]
        logger.info("lifespan.starting")

        # --- Recursion limit (SQLAlchemy UUID type resolution exceeds default 1000) ---
        import sys
        sys.setrecursionlimit(settings.PYTHON_RECURSION_LIMIT)

        # --- Startup hook (env-specific setup, dev warnings, etc.) ---
        if on_startup is not None:
            result = on_startup(app)
            if inspect.isawaitable(result):
                await result

        # --- Graceful shutdown signal handler ---
        if graceful_shutdown is not None:
            graceful_shutdown.install(app)

        # --- Startup validation ---
        if settings.PII_ENCRYPTION_ENABLED:
            from swx_core.security.encryption import validate_encryption_key
            validate_encryption_key()
            logger.info("Encryption key validated (PII encryption enabled).")

        # --- Database setup (skip in Docker — prestart script handles it) ---
        if not settings.DOCKERIZED:
            from swx_core.database.db_setup import setup_database
            await setup_database()
            logger.info("Database setup completed.")

            from swx_core.database.db_seed import seed_data
            await seed_data()
            logger.info("Initial data seeded.")

        # --- Audit integrity (SOC 2 CC7.2) ---
        # Ordered strictly AFTER setup_database() in the non-Docker path; in
        # Docker (prestart owns migrations) a still-migrating fresh DB shows
        # up as a missing table: wait bounded for it rather than crash-looping
        # (a restart loop can SIGKILL the alembic run mid-DDL).
        from swx_core.database.db import async_session
        from swx_core.services.compliance.audit_integrity_service import (
            check_startup_integrity,
            audit_table_exists,
        )

        if settings.DOCKERIZED:
            from asyncio import sleep as _sleep

            _wait_seconds = 120
            for _attempt in range(_wait_seconds // 5):
                async with async_session() as probe_session:
                    if await audit_table_exists(probe_session):
                        break
                logger.info("Audit table not present yet (migrations running); retrying in 5s (%d/%d)",
                            _attempt + 1, _wait_seconds // 5)
                await _sleep(5)
            else:
                logger.warning("Audit table still absent after %ss — skipping startup integrity check.", _wait_seconds)

        async with async_session() as integrity_session:
            try:
                await check_startup_integrity(integrity_session)
            except LookupError:
                logger.warning("Audit table absent — startup integrity check skipped (fresh database).")
        logger.info("Audit log integrity verified.")

        # --- System policies ---
        from swx_core.services.policy.policy_registry import register_system_policies
        register_system_policies()
        logger.info("System policies registered.")

        # --- Job handlers ---
        _register_core_job_handlers()

        # --- Webhook bridge ---
        from swx_core.events.listeners.webhook_bridge_listener import register_webhook_bridge
        register_webhook_bridge()
        logger.info("Webhook bridge listener registered.")

        # --- Start lifecycle services ---
        await lifecycle.start_all()

        yield  # --- Application is running ---

        # --- Shutdown ---
        logger.info("lifespan.shutting_down")
        await lifecycle.stop_all()
        logger.info("lifespan.shutdown_complete")

    return lifespan


def _register_core_job_handlers() -> None:
    """Register the standard set of job handlers."""
    from swx_core.services.job import register_job_handler
    from swx_core.services.job.handlers import (
        alert_send_handler,
        audit_aggregate_handler,
        billing_sync_handler,
        billing_webhook_handler,
        cache_refresh_handler,
        compliance_api_key_expired_cleanup_handler,
        compliance_data_subject_delete_handler,
        compliance_retention_apply_handler,
        compliance_session_idle_cleanup_handler,
    )
    from swx_core.models.job import JobType

    register_job_handler(JobType.billing_sync, billing_sync_handler)
    register_job_handler(JobType.billing_webhook, billing_webhook_handler)
    register_job_handler(JobType.alert_send, alert_send_handler)
    register_job_handler(JobType.audit_aggregate, audit_aggregate_handler)
    register_job_handler(JobType.cache_refresh, cache_refresh_handler)
    register_job_handler(JobType.compliance_data_subject_delete, compliance_data_subject_delete_handler)
    register_job_handler(JobType.compliance_retention_apply, compliance_retention_apply_handler)
    register_job_handler(JobType.compliance_api_key_expired_cleanup, compliance_api_key_expired_cleanup_handler)
    register_job_handler(JobType.compliance_session_idle_cleanup, compliance_session_idle_cleanup_handler)
    logger.info("Core job handlers registered.")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def create_swx_app(
    title: Optional[str] = None,
    app_name: str = "swx_app",
    *,
    register_routes: bool = True,
    register_middleware: bool = True,
    install_exception_handlers: bool = True,
    middleware_overrides: Optional[dict[str, bool]] = None,
    lifecycle_services: Optional[list[LifecycleService]] = None,
    providers: Optional[list[str]] = None,
    discover_user_providers: bool = True,
    validate_production_config: bool = True,
    production_validator: Optional["ProductionValidator"] = None,
    on_bootstrap: Optional[Callable[[FastAPI], None]] = None,
    on_startup: Optional[Callable[[FastAPI], Any]] = None,
    root_endpoint: bool = True,
    disable_docs_in_production: bool = False,
    graceful_shutdown: Optional[GracefulShutdown] = None,
    fastapi_kwargs: Optional[dict[str, Any]] = None,
) -> FastAPI:
    """Create a fully-configured SwX FastAPI application.

    This factory handles all framework plumbing so application entry points
    can be thin and declarative.

    Args:
        title: Application title (defaults to ``settings.PROJECT_NAME``).
        app_name: Application module name for discovery (defaults to
            ``"swx_app"``).  Set ``SWX_APP_NAME`` env var instead for
            runtime configuration.
        register_routes: Whether to include auto-discovered routes.
        register_middleware: Whether to apply the canonical middleware stack.
        install_exception_handlers: Whether to register standard handlers.
        middleware_overrides: Per-middleware enable/disable overrides.
        lifecycle_services: Additional ``LifecycleService`` instances to
            manage alongside the built-in ones.
        providers: Additional provider class paths to register.
        discover_user_providers: Whether to auto-discover app providers.
        validate_production_config: Whether to run built-in production checks.
        production_validator: Optional pre-built ``ProductionValidator``
            whose rules are merged with the built-in checks.  Use this
            to add app-specific production requirements (Stripe keys,
            email config, etc.) that block startup on failure.
        on_bootstrap: Callback invoked after bootstrap completes but before
            the app is returned.  Receives the ``app`` instance.
            **Must be synchronous** — called outside the async lifespan.
        on_startup: Callback invoked at the start of the lifespan, before
            any lifecycle services.  Receives the ``app`` instance.
            May be sync or async — if it returns an awaitable, it will
            be awaited.
        root_endpoint: Whether to add a ``GET /`` welcome endpoint.
            Set ``False`` if your application defines its own root route.
        disable_docs_in_production: When ``True``, automatically disables
            OpenAPI, Swagger, and ReDoc endpoints in production by setting
            ``openapi_url``, ``docs_url``, and ``redoc_url`` to ``None``.
        graceful_shutdown: Optional :class:`GracefulShutdown` instance.
            When provided, SIGTERM/SIGINT handlers are installed during
            lifespan startup so SSE/WebSocket connections drain before
            exit.  Access the instance via ``app.state.graceful_shutdown``.
        fastapi_kwargs: Extra keyword arguments forwarded to the
            ``FastAPI()`` constructor (e.g. ``description``,
            ``version``, ``docs_url``).

    Returns:
        A ``FastAPI`` application ready for ``uvicorn``.
    """
    from swx_core.config.discovery import reset_discovery

    if app_name != "swx_app":
        reset_discovery(app_name=app_name)

    title = title or settings.PROJECT_NAME

    # --- Production config validation ---
    if validate_production_config:
        from swx_core.config.validator import ProductionValidator
        validator = production_validator or ProductionValidator()
        errors = validator.validate(environment=settings.ENVIRONMENT)
        if errors:
            for error in errors:
                logger.critical("production_config.invalid: %s", error)
            if settings.ENVIRONMENT in ("production", "prod"):
                raise SystemExit(1)

    # --- Build lifecycle manager ---
    lifecycle = LifecycleManager()
    lifecycle.register(JobRunnerService())
    lifecycle.register(AuditQueueService())
    lifecycle.register(RedisBridgeService())

    if getattr(settings, "SIEM_ENABLED", False):
        lifecycle.register(_SIEMFlushService())

    lifecycle.register(_APIKeyLifecycleService())
    lifecycle.register(_SessionCleanupService())
    lifecycle.register(_CacheRefreshService())
    lifecycle.register(_SSEManagerService())
    lifecycle.register(_WSManagerService())

    if lifecycle_services:
        for svc in lifecycle_services:
            lifecycle.register(svc)

    # --- Disable docs in production ---
    if disable_docs_in_production and settings.ENVIRONMENT in ("production", "prod"):
        fastapi_kwargs = {**(fastapi_kwargs or {}), "openapi_url": None, "docs_url": None, "redoc_url": None}

    # --- Create FastAPI app ---
    fastapi_opts: dict[str, Any] = {
        "title": title,
        "openapi_url": f"{settings.ROUTE_PREFIX}/openapi.json",
        "lifespan": _build_lifespan(lifecycle, on_startup=on_startup, graceful_shutdown=graceful_shutdown),
    }
    if fastapi_kwargs:
        fastapi_opts.update(fastapi_kwargs)

    app = FastAPI(**fastapi_opts)

    app.state.environment = settings.ENVIRONMENT

    from swx_core.utils.health import get_health_checker
    app.state.health_checker = get_health_checker()

    # --- Realtime stats health check ---
    from swx_core.realtime.stats import StatsCollector
    from swx_core.sse.manager import SSEManager

    realtime_stats = StatsCollector()
    app.state.realtime_stats = realtime_stats
    app.state.health_checker.add_check("realtime", realtime_stats.health_check, required=False)

    sse_manager = SSEManager.create(stats=realtime_stats)
    app.state.sse_manager = sse_manager

    from swx_core.websocket.manager import ConnectionManager
    ws_manager = ConnectionManager.create(stats=realtime_stats)
    app.state.ws_manager = ws_manager

    if graceful_shutdown is not None:
        app.state.graceful_shutdown = graceful_shutdown

    # --- Exception handlers ---
    if install_exception_handlers:
        register_exception_handlers(app)

    # --- Middleware stack ---
    if register_middleware:
        apply_middleware_stack(app, overrides=middleware_overrides)

    # --- Routes ---
    if register_routes:
        app.include_router(router)

    # --- Bootstrap (providers, hooks, listeners) ---
    from swx_core.bootstrap import bootstrap_app
    bootstrap_app(app, providers=providers, discover_user_providers=discover_user_providers, register_middleware=False)

    # --- Post-bootstrap hook ---
    if on_bootstrap is not None:
        on_bootstrap(app)

    # --- Root endpoint ---
    if root_endpoint:
        @app.get("/")
        def root():
            return {"message": f"Welcome to {title}"}

    return app