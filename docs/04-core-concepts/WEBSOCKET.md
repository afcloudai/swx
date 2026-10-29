# WebSocket Connection Manager & Cross-Worker Relay

**Version:** 2.28.0
**Last Updated:** 2026-09-10

## Overview

The WebSocket layer provides reliable, single-connection-per-key management with
cross-worker message relay via Redis Pub/Sub. It solves two problems:

1. **Fork safety** — Under Gunicorn's pre-fork model, a module-level
   `ConnectionManager()` copies an empty `_connections` dict into every worker.
   The singleton `create()`/`get_instance()` pattern ensures the manager is
   created **after** fork, in the lifespan startup.

2. **Cross-worker delivery** — Without a Redis bridge, `send()` and `broadcast()`
   only reach connections on the same worker. `WSRedisBridge` mirrors the
   `SSERedisBridge` architecture to relay messages across all workers.

## Architecture

```
Worker 1: ws_manager.send("device-42", payload)
  ├─ Local delivery to connection on Worker 1 (zero latency)
  └─ Published to Redis: swx:ws:send
                    │
                Redis Server
                    │
        ┌───────────┼───────────┐
        ▼           ▼           ▼
   Worker 1    Worker 2    Worker 3
   (skipped,   (local      (local
    _source=    delivery)   delivery)
    "redis_ws")
```

1. **Local send** runs first — zero latency for the originating worker.
2. **Redis publish** fans out to all subscribed workers.
3. **Loop prevention** — messages from Redis carry `_broadcast_source="redis_ws"`
   and are delivered locally only; they are never re-published.

## Connection Manager

### Singleton Pattern

Always use `ConnectionManager.create()` (called once in `create_swx_app()`)
and `ConnectionManager.get_instance()` in routes:

```python
# app_factory.py (lifespan startup)
ws_manager = ConnectionManager.create(stats=realtime_stats)

# ws_route.py (per-request)
mgr = ConnectionManager.get_instance()
if mgr is None:
    await websocket.close(code=1011, reason="WebSocket manager not initialised")
    return
await mgr.connect(device_id, websocket)
```

**Never** instantiate `ConnectionManager()` at module level — it will be
fork-copied with an empty `_connections` dict.

### Connect / Disconnect

```python
# Basic — manager accepts the WebSocket
await mgr.connect(device_id, websocket)

# With auth — accept yourself, then register
await websocket.accept()
user = await authenticate(websocket)
await mgr.connect(device_id, websocket, accept=False,
                  metadata={"user_id": user.id, "ip": client_ip})
```

The `metadata` dict is stored on the connection and returned by
`connection_info()` and `all_connection_info()` for observability. It is
never sent to the client.

### Send / Broadcast

```python
# Directed send (queues for drain-on-reconnect if offline)
sent = await mgr.send("device-42", json.dumps({"type": "order.update"}))

# Broadcast to all connections (optionally exclude one)
count = await mgr.broadcast(json.dumps({"type": "system.maintenance"}),
                            exclude="device-99")
```

Both `send()` and `broadcast()` publish to Redis when the bridge is
configured, so the message reaches connections on **all** workers.

### Observability

```python
# Per-connection metadata
info = mgr.connection_info("device-42")
# {"key": "device-42", "worker_id": 12345, "connected_at": 17259..., 
#  "pending_messages": 0, "metadata": {"user_id": "abc", "ip": "1.2.3.4"}}

# All connections on this worker
all_info = mgr.all_connection_info()

# Aggregate metrics
metrics = mgr.metrics
# {"opened": 5, "closed": 2, "sent": 120, "queued": 3, "failed": 1}

# Manager state
mgr.status         # "running" or "stopped"
mgr.worker_id      # PID of this worker
mgr.connection_count  # number of active connections
mgr.bridge_stats   # Redis bridge stats, or None
```

### Admin Endpoint

```
GET /admin/ws/status
```

Returns:

```json
{
  "status": "running",
  "worker_id": 12345,
  "active_connections": 3,
  "connections": {
    "device-42": {
      "key": "device-42",
      "worker_id": 12345,
      "connected_at": 1725986000.0,
      "pending_messages": 0,
      "metadata": {"user_id": "abc", "ip": "1.2.3.4"}
    }
  },
  "metrics": {"opened": 5, "closed": 2, "sent": 120, "queued": 3, "failed": 1},
  "redis_bridge": {
    "running": true,
    "redis_connected": true,
    "channel_prefix": "swx:ws",
    "worker_id": 12345,
    "reconnect_attempts": 0,
    "messages_published": 45,
    "messages_relayed": 38
  }
}
```

## Redis Bridge

### Configuration

| Setting | Default | Description |
|---|---|---|
| `REDIS_ENABLED` | `True` | Required. Redis must be enabled for the bridge to activate. |
| `WS_BRIDGE_ENABLED` | `True` | Enable/disable cross-worker WebSocket relay. Set to `False` to keep messages in-process only. |
| `WS_BRIDGE_CHANNEL_PREFIX` | `swx:ws` | Redis channel prefix. Useful for isolating environments (e.g., `staging:ws`). |

```bash
# .env — minimal config (bridge is enabled by default when Redis is on)
REDIS_ENABLED=True
REDIS_URL=redis://:password@redis-host:6379/0

# Disable the bridge (messages stay in-process only)
WS_BRIDGE_ENABLED=False
```

### Lifecycle

The bridge is wired automatically by `_WSManagerService` in
`create_swx_app()`:

1. `ConnectionManager.create(stats=realtime_stats)` — creates the singleton
2. `await mgr.start()` — marks the manager as running
3. If `REDIS_ENABLED` and `WS_BRIDGE_ENABLED`, creates and starts
   `WSRedisBridge`, then sets `mgr._redis_bridge = bridge`
4. On shutdown: `await bridge.stop()` then `await mgr.stop()`

### Loop Prevention

```
Worker 1: send("device-42", message)
  → local delivery ✓
  → _publish_to_redis() → bridge.publish({"action":"send", ..., "_broadcast_source":"redis_ws"})

Worker 2: _listen_loop() receives message
  → _handle_message() → _deliver_from_redis(action="send", key="device-42", msg=...)
  → local delivery ✓
  → _deliver_from_redis does NOT call _publish_to_redis (structural guarantee)
```

The bridge adds `_broadcast_source="redis_ws"` and `worker_id` to every
Redis envelope. `_deliver_from_redis()` never calls `_publish_to_redis()`,
so there is no re-publish path and no fan-out loop.

### Reconnection

If the Redis connection drops, the listener:

1. Logs the error and increments `reconnect_attempts`
2. Waits `RECONNECT_DELAY` seconds (default 5s)
3. Closes the old pubsub, creates a new one, re-subscribes
4. Resets the attempt counter on success
5. Stops after `MAX_RECONNECT_ATTEMPTS` if configured

## Pending Message Queue

Each connection key has a 64-message overflow buffer. When a connection is
offline, messages are queued and drained on reconnect:

1. `send("device-42", msg)` — device is offline → message queued
2. Device reconnects → `connect()` drains pending messages to the new socket
3. Heartbeat (`heartbeat()`) also drains pending messages

Messages from Redis that target an offline connection are also queued
locally, so messages sent from any worker are preserved.

## Comparison with SSE

| Feature | SSE | WebSocket |
|---|---|---|
| Singleton | `SSEManager.create()` | `ConnectionManager.create()` |
| Lifecycle service | `_SSEManagerService` | `_WSManagerService` |
| Redis bridge | `SSERedisBridge` | `WSRedisBridge` |
| Channel prefix | `swx:sse` | `swx:ws` |
| Bridge setting | `SSE_BRIDGE_ENABLED` | `WS_BRIDGE_ENABLED` |
| Loop marker | `_broadcast_source="redis_sse"` | `_broadcast_source="redis_ws"` |
| Admin endpoint | `GET /admin/realtime` (via StatsCollector) | `GET /admin/ws/status` |
| Connection model | Many per channel (fan-out) | One per key (replace) |

## Migrating from In-Process to Multi-Worker

If you previously used `ConnectionManager()` at module level:

1. **Remove** the module-level instantiation in your route file
2. **Use** `ConnectionManager.get_instance()` at request time
3. **Ensure** `create_swx_app()` is used (it creates the singleton and
   wires the bridge automatically)
4. **Set** `REDIS_ENABLED=True` and `WS_BRIDGE_ENABLED=True` in your
   environment (these are the defaults)

No other code changes are needed — `send()`, `broadcast()`, `connect()`,
and `disconnect()` work identically in single-worker and multi-worker
setups.