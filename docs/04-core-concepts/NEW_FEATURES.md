# SwX Core v2 — New Features Guide

This document covers the new framework capabilities added in the v2 architecture audit. Each section includes motivation, API reference, and usage examples.

---

## Table of Contents

1. [Application Factory](#1-application-factory)
2. [Lifecycle Manager](#2-lifecycle-manager)
3. [Background Scheduler](#3-background-scheduler)
4. [Production Configuration Validator](#4-production-configuration-validator)
5. [Exception Handlers](#5-exception-handlers)
6. [Middleware Stack](#6-middleware-stack)
7. [Health & Readiness Endpoints](#7-health--readiness-endpoints)
8. [Container Improvements](#8-container-improvements)
9. [Bootstrap Improvements](#9-bootstrap-improvements)

---

## 1. Application Factory

**Module:** `swx_core.app_factory`

The `create_swx_app()` factory replaces the 370-line `main.py` with a single declarative call. It wires up lifecycle services, exception handlers, middleware, routes, and production config validation.

### Usage

```python
from swx_core import create_swx_app

app = create_swx_app(
    title="MyApp API",
    app_name="my_app",
)

# Override middleware (disable CSRF, enable metrics):
app = create_swx_app(
    middleware_overrides={"csrf": False, "metrics": True},
)

# Add custom lifecycle services:
from swx_core.lifecycle import LifecycleService

class MyService(LifecycleService):
    name = "my_service"
    async def start(self): ...
    async def stop(self): ...

app = create_swx_app(lifecycle_services=[MyService()])
```

### Parameters

| Parameter | Type | Default | Description |
|---|---|---|---|
| `title` | `str \| None` | `settings.PROJECT_NAME` | App title |
| `app_name` | `str` | `"swx_app"` | Module name for discovery |
| `register_routes` | `bool` | `True` | Include auto-discovered routes |
| `register_middleware` | `bool` | `True` | Apply canonical middleware stack |
| `register_exception_handlers` | `bool` | `True` | Register standard exception handlers |
| `middleware_overrides` | `dict[str, bool] \| None` | `None` | Per-middleware enable/disable |
| `lifecycle_services` | `list[LifecycleService] \| None` | `None` | Additional lifecycle services |
| `validate_production_config` | `bool` | `True` | Run production config checks |

---

## 2. Lifecycle Manager

**Module:** `swx_core.lifecycle`

Deterministic startup/shutdown for long-running services. Services start in registration order and stop in **reverse** order.

### Classes

- **`LifecycleService`** — Abstract base class. Subclass and implement `start()` and `stop()`.
- **`LifecycleManager`** — Registry that orchestrates start/stop.
- **`LifecycleError`** — Raised on startup failure with `service_name`, `action`, and `detail` fields.

### Usage

```python
from swx_core.lifecycle import LifecycleManager, LifecycleService

class CacheWarmer(LifecycleService):
    name = "cache_warmer"

    async def start(self):
        # Connect to Redis, warm caches
        ...

    async def stop(self):
        # Graceful shutdown
        ...

manager = LifecycleManager()
manager.register(CacheWarmer())

# In FastAPI lifespan:
await manager.start_all()   # starts in order
# ... app runs ...
await manager.stop_all()      # stops in reverse order
```

### Key Rules

- `name` attribute is **required** — raises `ValueError` if empty.
- Start failures propagate as `LifecycleError` and trigger rollback (stop already-started services).
- Stop failures are **logged but never raised** — shutdown must be resilient.

---

## 3. Background Scheduler

**Module:** `swx_core.background`

Declarative recurring task registration with graceful shutdown. Replaces hand-rolled `while True: … await asyncio.sleep(N)` loops.

### Usage

```python
from swx_core.background import background

# Register a recurring job
background.register(
    name="cache_refresh",
    handler=refresh_translation_cache,
    interval=3600,          # seconds
)

# Delay first run until one interval has passed
background.register(
    name="metrics_push",
    handler=push_metrics,
    interval=60,
    startup=False,          # wait 60s before first run
)

# Crash on error (default: log and continue)
background.register(
    name="critical_sync",
    handler=critical_sync,
    interval=30,
    error_policy="raise",
)

# Start/stop with app lifecycle
await background.start()
await background.stop()
```

### Module-Level Singleton

`background` is a pre-created module-level singleton. You can also create isolated instances:

```python
from swx_core.background import BackgroundScheduler
my_scheduler = BackgroundScheduler()
```

---

## 4. Production Configuration Validator

**Module:** `swx_core.config.validator`

Extensible mechanism for declaring production configuration requirements. Invalid config fails fast with actionable errors.

### Usage

```python
from swx_core.config.validator import ProductionValidator

validator = ProductionValidator()
validator.require("STRIPE_API_KEY")
validator.require("DATABASE_URL")
validator.forbid_localhost("FRONTEND_HOST")
validator.forbid_localhost("API_BASE_URL")
validator.check(
    lambda: not settings.DEBUG,
    "DEBUG must be False in production",
)

errors = validator.validate(environment=settings.ENVIRONMENT)
if errors:
    for error in errors:
        print(f"  ✗ {error}")
    raise SystemExit(1)
```

### Key Behavior

- **Non-production environments are a no-op by default.** `validate(environment="local")` returns `[]`.
- Placeholder patterns are rejected: `<KEY>`, `${VAR}`, `$VAR`, `sk_test_mock*`, `pk_test_mock*`, `whsec_mock*`.
- `forbid_localhost` catches `localhost`, `127.0.0.1`, and `0.0.0.0`.
- All rule builders are **chainable**: `validator.require("A").forbid_localhost("B").check(cond, "msg")`.

---

## 5. Exception Handlers

**Module:** `swx_core.exceptions.handlers`

Production-safe exception handlers for FastAPI. Call `register_exception_handlers(app)` during setup.

### Handlers

| Handler | Exception Type | Response |
|---|---|---|
| `swx_error_handler` | `SwXError` | Structured JSON from `exc.to_dict()` |
| `validation_error_handler` | `RequestValidationError` | 422 with sanitized details |
| `http_error_handler` | `StarletteHTTPException` | `{"error": exc.detail}` |
| `generic_error_handler` | `Exception` (catch-all) | 500 — **production never leaks internals** |

### Production Safety

In production (`environment` in `app.state` = `"production"` | `"prod"`), the generic 500 handler returns:

```json
{"error": "Internal Server Error", "request_id": "...", "correlation_id": "..."}
```

In non-production, it includes `"detail"` and `"type"` fields for debugging.

### Usage

```python
from swx_core.exceptions.handlers import register_exception_handlers
from fastapi import FastAPI

app = FastAPI()
register_exception_handlers(app)
```

This is done automatically by `create_swx_app()`.

---

## 6. Middleware Stack

**Module:** `swx_core.middleware.stack`

Canonical, security-ordered middleware configuration. Middleware is applied in LIFO order (FastAPI convention), so the list specifies the **logical** outer-to-inner order.

### Canonical Order

| Order | Name | Required | Default |
|---|---|---|---|
| 10 | `cors` | Yes | Enabled |
| 20 | `security_headers` | Yes | Enabled |
| 30 | `audit` | Yes | Enabled |
| 40 | `logging` | Yes | Enabled |
| 50 | `rate_limit` | Yes | Enabled |
| 60 | `auth_rate_limit` | Yes | Enabled |
| 70 | `rate_limit_headers` | Yes | Enabled |
| 80 | `tenant` | Yes | Enabled |
| 90 | `csrf` | No | Enabled |
| 100 | `container` | No | Enabled |
| 110 | `session` | Yes | Enabled |
| 120 | `metrics` | No | Disabled |
| 130 | `region_routing` | No | Disabled |

### Usage

```python
from swx_core.middleware.stack import apply_middleware_stack

# Default stack
apply_middleware_stack(app)

# With overrides
apply_middleware_stack(app, overrides={"csrf": False, "metrics": True})
```

Disabling a **required** layer logs a warning. Disabling an optional layer logs info.

---

## 7. Health & Readiness Endpoints

**Routes:** `GET /utils/health-check`, `GET /utils/health`, `GET /utils/ready`

### Endpoint Comparison

| Endpoint | Purpose | Status Code | Response |
|---|---|---|---|
| `/utils/health-check` | **Liveness** — is the process alive? | Always 200 | `{"status": "healthy", "service": "swx-api"}` |
| `/utils/health` | **Detailed health** — how are all services? | 200 or 503 | Full `HealthCheckResult` with per-service status |
| `/utils/ready` | **Readiness** — can we accept traffic? | 200 or 503 | Only fails if *required* services are unhealthy |

### HealthChecker Integration

The `HealthChecker` from `swx_core.utils.health` is wired to `app.state.health_checker` by `create_swx_app()`. You can add custom checks:

```python
from swx_core.utils.health import get_health_checker

checker = get_health_checker()
checker.add_check("elastic", check_elastic, required=False)
```

### Kubernetes Configuration

```yaml
livenessProbe:
  httpGet:
    path: /utils/health-check
    port: 8001

readinessProbe:
  httpGet:
    path: /utils/ready
    port: 8001
```

---

## 8. Container Improvements

### Modular Structure

The container has been split into focused modules:

| Module | Contents |
|---|---|
| `swx_core.container.binding` | `BindingType`, `Binding`, `ContainerError`, `BindingResolutionError`, `CircularDependencyError`, `ContextualBinding` |
| `swx_core.container.container` | `Container` class, `get_container()`, `set_container()`, `reset_container()` |
| `swx_core.container.__init__` | Backward-compatible re-exports of all public names |

**All existing imports continue to work.** No migration needed.

### New: `has()` Method

```python
container = Container()
container.bind("cache", RedisCache)

container.has("cache")    # True
container.has("missing")  # False

# Equivalent to:
container.bound("cache")  # True
```

### New: `override()` Method

Replace a binding and clear cached singleton instances:

```python
container.singleton("email", SMTPEmailProvider)
container.override("email", SendGridProvider)
container.make("email")  # SendGridProvider (new singleton)
```

### Bug Fix: Circular Dependency Detection

String-based circular dependencies (e.g., `bind("a", "b"); bind("b", "a")`) now correctly raise `CircularDependencyError` instead of `RecursionError`. The `_build_stack` is properly pushed/popped in `Container.make()` for all resolution paths.

---

## 9. Bootstrap Improvements

**Module:** `swx_core.bootstrap`

The bootstrap process now includes:

- **`BootstrapStage` enum** — `PROVIDERS`, `ROUTES`, `HOOKS`, `LISTENERS`, `CUSTOM` for deterministic ordering.
- **`BootstrapResult` dataclass** — structured result with `stages`, `duration`, and `errors`.
- **`CircularProviderError`** — raised when provider `depends` chains form a cycle (DFS detection).
- **`_log_stage()`** — structured timing per stage.

### Usage

```python
from swx_core.bootstrap import bootstrap_app, BootstrapResult

result: BootstrapResult = bootstrap_app(app)
print(f"Bootstrapped in {result.duration:.2f}s")
for stage in result.stages:
    print(f"  {stage.name}: {stage.duration:.3f}s")
```

---

## Migration Notes

### From Old `main.py` to `create_swx_app()`

If your `main.py` manually calls `bootstrap_app()`, registers middleware, sets up exception handlers, etc., you can replace all of it with:

```python
from swx_core import create_swx_app

app = create_swx_app(title="MyApp API")
```

For advanced cases, pass `lifecycle_services`, `middleware_overrides`, or `providers` as needed.

### Container Import Changes

All existing imports work unchanged:

```python
# Still works:
from swx_core.container import Container, Binding, BindingType
from swx_core.container.container import Container, get_container

# Also works:
from swx_core.container.binding import BindingType
```

---

## 10. Real-Time Infrastructure (v2.26.3)

### SSE Manager

**Module:** `swx_core.sse.manager`

Channel-based Server-Sent Events with pluggable event store backends.

```python
from swx_core.sse.manager import SSEManager
from swx_core.sse.stores import InMemorySSEEventStore

manager = SSEManager(store=InMemorySSEEventStore(max_events=100))

# Add a client to a channel
queue = await manager.subscribe("orders")

# Broadcast to all subscribers on a channel
await manager.broadcast("orders", {"event": "order.created", "data": {...}})

# Disconnect a client
await manager.unsubscribe("orders", client_id)
```

For multi-worker deployments, use `RedisSSEEventStore`:

```python
from swx_core.sse.stores import RedisSSEEventStore

manager = SSEManager(store=RedisSSEEventStore(redis_url="redis://localhost"))
```

### SSE↔EventBus Bridge

**Module:** `swx_core.sse.bridge`

Declaratively bridge `EventBus` events to SSE channels.

```python
from swx_core.sse.bridge import sse_bridge

# Bridge an event type to an SSE channel
sse_bridge.bridge("order.created", "orders")
sse_bridge.bridge("payment.received", "payments")

# Start/stop with app lifecycle
await sse_bridge.start()
await sse_bridge.stop()
```

### SSE Event Serializer Registry

**Module:** `swx_core.sse.serializer`

Register custom serializers per event type for SSE payloads.

```python
from swx_core.sse.serializer import sse_serializers

# Register a custom serializer
sse_serializers.register("order.created", lambda data: {
    "event": "order_created",
    "id": data["id"],
    "total": f"${data['total']:.2f}",
})

# Serialize an event payload
payload = sse_serializers.serialize("order.created", {"id": 123, "total": 49.99})

# Unregister when no longer needed
sse_serializers.unregister("order.created")
```

### WebSocket Connection Manager

**Module:** `swx_core.websocket.manager`

Single-connection-per-key enforcement with pending message queue.

```python
from swx_core.websocket.manager import ConnectionManager

manager = ConnectionManager()

# Accept a connection (replaces any existing connection for the same key)
await manager.connect("user:42", websocket)

# Send a message (queues if client is temporarily disconnected)
await manager.send("user:42", {"type": "chat", "text": "Hello"})

# Disconnect
await manager.disconnect("user:42")
```

### WebSocket↔EventBus Bridge

**Module:** `swx_core.websocket.bridge`

Declaratively bridge `EventBus` events to WebSocket targets.

```python
from swx_core.websocket.bridge import ws_bridge

# Bridge an event type to a WebSocket target
ws_bridge.bridge("chat.message", target="user:{sender_id}")
ws_bridge.bridge("system.alert", target="broadcast")

await ws_bridge.start()
await ws_bridge.stop()
```

### StatsCollector

**Module:** `swx_core.realtime.stats`

Per-channel, per-connection, and per-listener metrics for SSE, WebSocket, and EventBus.

```python
from swx_core.realtime.stats import StatsCollector

stats = StatsCollector()

# Record events
stats.record_sse_broadcast("orders", events_count=1)
stats.record_ws_message("user:42", direction="outgoing")

# Health check
health = stats.health_check()
# {"sse": {"channels": 3, "active_connections": 12}, "ws": {...}, ...}
```

---

## 11. Observability (v2.26.3)

### Correlation ID Middleware

**Module:** `swx_core.middleware.correlation_id_middleware`

Generates a UUID correlation ID per request, stored in `scope["state"]["correlation_id"]` and added as `X-Correlation-ID` to the response.

```python
from swx_core.middleware.correlation_id_middleware import CorrelationIdMiddleware

app.add_middleware(CorrelationIdMiddleware)

# Access in a route handler:
async def my_route(request: Request):
    correlation_id = request.scope["state"]["correlation_id"]
    ...
```

### Database Pool Health Check

**Module:** `swx_core.routes.utils.health`

Verifies the SQLAlchemy async connection pool is accepting connections.

```python
from swx_core.routes.utils.health import check_database_pool

result = await check_database_pool()
# {"status": "healthy", "pool_size": 5, "checked_out": 2}
```

---

## 12. Graceful Shutdown (v2.26.3)

**Module:** `swx_core.lifecycle.graceful_shutdown`

Orchestrates orderly shutdown: drains in-flight requests, closes SSE/WebSocket connections, cancels background tasks, then stops providers.

```python
from swx_core.lifecycle.graceful_shutdown import GracefulShutdown

shutdown = GracefulShutdown(timeout=30.0)  # seconds to wait for drain

# Install in app
app = create_swx_app(graceful_shutdown=shutdown)

# Or manually:
shutdown.install(app)

# Access from app state:
shutdown = app.state.graceful_shutdown
```

Wired into `create_swx_app()` automatically. No additional configuration needed unless you want custom timeout.

---

## 13. Production Hardening (v2.26.3)

### Disable Docs in Production

Prevents OpenAPI schema leakage in production environments.

```python
app = create_swx_app(disable_docs_in_production=True)
```

When `ENVIRONMENT=production`, `/docs` and `/redoc` return 404 and `openapi_url` is set to `None`.

### Production Validator

Custom startup validation that runs during lifespan startup.

```python
def validate_my_config(settings) -> list[str]:
    warnings = []
    if not settings.STRIPE_API_KEY:
        warnings.append("STRIPE_API_KEY is required for billing")
    return warnings

app = create_swx_app(production_validator=validate_my_config)
```

### On-Startup Hook

One-time warm-up code executed after providers boot but before the app accepts requests.

```python
async def warm_up():
    await prime_cache()
    await sync_feature_flags()

app = create_swx_app(on_startup=warm_up)
```

---

## 14. Background Task Failure Alerts (v2.26.3)

**Module:** `swx_core.background`

`BackgroundScheduler` now tracks consecutive failures per `ScheduledJob` and emits alerts via `AlertEngine` when the count exceeds `alert_threshold` (default 3).

```python
from swx_core.background import background

# Register with custom alert threshold
background.register(
    name="critical_sync",
    handler=critical_sync,
    interval=30,
    alert_threshold=2,  # alert after 2 consecutive failures
)

# Check failure counts for monitoring
counts = background.get_failure_counts()
# {"critical_sync": 3, "cache_refresh": 0}
```

---

## 15. Per-Route Rate Limiting (v2.26.3)

**Module:** `swx_core.services.rate_limit.per_route`

Exact-path and regex-pattern rate limits applied via FastAPI dependency.

```python
from swx_core.services.rate_limit.per_route import route_limits, rate_limit
from fastapi import APIRouter, Depends

# --- Style 1: Bulk registration at app startup ---
route_limits.configure({
    "/api/search": {"get": "100/hour"},
    "/api/detect/public": {"post": "5/minute"},
})

# --- Style 2: Decorator/dependency on individual routes ---
router = APIRouter()

@router.post("/api/detect/public", dependencies=[Depends(rate_limit("5/minute", namespace="detection:detect:public"))])
async def detect_public(request: Request):
    ...

@router.get("/api/search", dependencies=[Depends(rate_limit("100/hour", namespace="search:query"))])
async def search(q: str):
    ...
```

---

## 16. Email/SMS Sender Registration (v2.26.3)

**Module:** `swx_core.services.notifications.provider_factory`

Register custom email and SMS sender backends without subclassing.

```python
from swx_core.services.notifications.provider_factory import (
    register_email_sender,
    register_sms_sender,
)

# Register a custom email sender
register_email_sender("sendgrid", SendGridEmailSender)

# Register a custom SMS sender
register_sms_sender("twilio", TwilioSMSSender)
```