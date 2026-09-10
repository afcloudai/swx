"""
WebSocket Connection Manager
-----------------------------
Reliable connection management with:

* **Single-connection-per-key** — new connection replaces old.
* **Pending message queue** — 64-message per-key overflow buffer.
  Oldest messages are dropped when the queue is full.
* **drain_pending()** — on heartbeat/registration, queued messages
  are flushed to the reconnected client.
* **Cross-worker relay** — optional ``WSRedisBridge`` publishes
  ``send`` and ``broadcast`` to Redis so other workers deliver to
  their local connections.
* **Worker metadata** — each connection records which worker process
  owns it, plus arbitrary metadata supplied at connect time.
* **Structured logging** — all log entries include ``worker_id`` and
  connection counts for full observability.

Singleton lifecycle
~~~~~~~~~~~~~~~~~~~

Use ``ConnectionManager.create()`` to initialise the global singleton
*after* the gunicorn fork (in the lifespan startup).  This avoids the
classic fork-safety bug where a module-level ``ConnectionManager()``
copies an empty ``_connections`` dict into every worker.

Typical usage in a FastAPI route::

    from swx_core.websocket import ConnectionManager

    # In app_factory lifespan startup:
    ws_mgr = ConnectionManager.create(stats=realtime_stats)

    # In the route (auto-discovered):
    @router.websocket("/ws/{device_id}")
    async def ws_endpoint(websocket: WebSocket, device_id: str):
        mgr = ConnectionManager.get_instance()
        await mgr.connect(device_id, websocket)
        ...

Advanced — accept after auth::

    @router.websocket("/ws/{device_id}")
    async def ws_endpoint(websocket: WebSocket, device_id: str):
        await websocket.accept()
        user = await authenticate(websocket)
        await mgr.connect(device_id, websocket, accept=False,
                          metadata={"user_id": user.id})
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Deque, Dict, Optional

from fastapi import WebSocket

from swx_core.realtime.stats import StatsCollector

logger = logging.getLogger(__name__)

_MAX_PENDING = 64

SOURCE_META_KEY = "_broadcast_source"
SOURCE_REDIS_WS = "redis_ws"

_WORKER_ID = os.getpid()


@dataclass
class _Connection:
    """Internal bookkeeping for a single WebSocket connection."""

    websocket: WebSocket
    connected_at: float = field(default_factory=time.monotonic)
    pending: Deque[str] = field(default_factory=lambda: deque(maxlen=_MAX_PENDING))
    metadata: Dict[str, Any] = field(default_factory=dict)
    worker_id: int = field(default_factory=lambda: _WORKER_ID)


class ConnectionManager:
    """Framework-level WebSocket connection manager.

    Enforces one active connection per key.  When a new connection
    arrives for an existing key, the old one is replaced.  Disconnected
    keys accumulate pending messages that are drained on reconnect.

    Cross-worker delivery is handled by an optional ``WSRedisBridge``.
    When configured, ``send()`` and ``broadcast()`` publish to Redis
    so that other workers can relay to their local connections.
    Messages arriving from Redis carry a ``_broadcast_source="redis_ws"``
    marker; the manager skips Redis re-publish for these to prevent
    fan-out loops.
    """

    _instance: Optional["ConnectionManager"] = None

    def __init__(
        self,
        stats: Optional[StatsCollector] = None,
        max_pending: int = _MAX_PENDING,
    ) -> None:
        self._stats = stats
        self._max_pending = max_pending
        self._connections: Dict[str, _Connection] = {}
        self._disconnected_pending: Dict[str, Deque[str]] = {}
        self._metrics = _ConnectionMetrics()
        self._redis_bridge: Any = None
        self._running = False

    @classmethod
    def get_instance(cls) -> Optional["ConnectionManager"]:
        """Return the global singleton instance (or ``None`` if not created)."""
        return cls._instance

    @classmethod
    def create(
        cls,
        stats: Optional[StatsCollector] = None,
        max_pending: int = _MAX_PENDING,
    ) -> "ConnectionManager":
        """Create and register the global singleton instance."""
        cls._instance = cls(stats=stats, max_pending=max_pending)
        return cls._instance

    @property
    def worker_id(self) -> int:
        """PID of the worker process this manager lives in."""
        return _WORKER_ID

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        """Mark the manager as running.  Called during app lifespan startup."""
        if self._running:
            return
        self._running = True
        logger.info("ws.manager.started worker=%d", _WORKER_ID)

    async def stop(self) -> None:
        """Gracefully close all connections and mark as stopped."""
        self._running = False
        for key, conn in list(self._connections.items()):
            try:
                await conn.websocket.close()
            except Exception:
                pass
        conn_count = len(self._connections)
        self._connections.clear()
        self._disconnected_pending.clear()
        logger.info("ws.manager.stopped worker=%d closed=%d", _WORKER_ID, conn_count)

    # ------------------------------------------------------------------
    # Connect / Disconnect
    # ------------------------------------------------------------------

    async def connect(
        self,
        key: str,
        websocket: WebSocket,
        *,
        accept: bool = True,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Register *websocket* under *key*.

        If *accept* is ``True`` (the default), ``await websocket.accept()``
        is called before registration.  Pass ``accept=False`` when the caller
        has already accepted the WebSocket.

        *metadata* is an optional dict stored on the connection for
        observability (e.g. ``{"user_id": "abc", "ip": "1.2.3.4"}``).
        It is returned by ``connection_info()`` but never sent to the client.

        If a connection already exists for *key*, it is replaced (the old
        socket is closed).  Pending messages are drained to the new connection.
        """
        if accept:
            await websocket.accept()

        existing = self._connections.get(key)
        if existing is not None:
            logger.info(
                "ws.replace key=%s worker=%d old_worker=%s old_meta=%s",
                key, _WORKER_ID, existing.worker_id, existing.metadata,
            )
            try:
                await existing.websocket.close()
            except Exception:
                pass

        conn = _Connection(
            websocket=websocket,
            metadata=metadata or {},
        )
        self._connections[key] = conn

        pending = self._disconnected_pending.pop(key, None)
        if pending:
            for msg in pending:
                conn.pending.append(msg)

        self._metrics.opened += 1

        if self._stats:
            await self._stats.ws_connect(key)
            await self._stats.ws_heartbeat(key)

        await self._drain_pending(key, conn)

        logger.info(
            "ws.connected key=%s worker=%d total=%d meta=%s",
            key, _WORKER_ID, len(self._connections), conn.metadata,
        )

    async def disconnect(self, key: str) -> None:
        """Remove the connection for *key* (best-effort close).

        Pending messages on the connection are preserved in a
        disconnected-pending buffer so they can be drained on reconnect.
        """
        conn = self._connections.pop(key, None)
        if conn is None:
            return

        if conn.pending:
            self._disconnected_pending[key] = conn.pending
        else:
            self._disconnected_pending.pop(key, None)

        try:
            await conn.websocket.close()
        except Exception:
            pass

        self._metrics.closed += 1

        if self._stats:
            await self._stats.ws_disconnect(key)

        logger.info(
            "ws.disconnected key=%s worker=%d remaining=%d meta=%s",
            key, _WORKER_ID, len(self._connections), conn.metadata,
        )

    # ------------------------------------------------------------------
    # Send
    # ------------------------------------------------------------------

    async def send(self, key: str, message: str) -> bool:
        """Send *message* to the connection identified by *key*.

        If the connection is active, sends immediately and publishes
        to Redis (when bridge is configured).  If the connection is
        offline, queues the message for drain-on-reconnect and still
        publishes to Redis so another worker may deliver it.

        Returns ``True`` if sent locally, ``False`` if queued.

        Raises:
            ValueError: If *key* is empty.
        """
        if not key:
            raise ValueError("Connection key must not be empty")

        sent_locally = await self._send_local(key, message)
        self._publish_to_redis("send", key, message)
        return sent_locally

    async def _send_local(self, key: str, message: str) -> bool:
        """Attempt local delivery.  Returns True if sent, False if queued."""
        conn = self._connections.get(key)
        if conn is not None:
            try:
                await conn.websocket.send_text(message)
                self._metrics.sent += 1
                if self._stats:
                    await self._stats.ws_sent(key)
                logger.debug("ws.sent key=%s worker=%d len=%d", key, _WORKER_ID, len(message))
                return True
            except Exception:
                logger.warning("ws.send_failed key=%s worker=%d (will queue)", key, _WORKER_ID)
                self._metrics.failed += 1
                if self._stats:
                    await self._stats.ws_failed(key)

        self._queue_pending(key, message)
        return False

    async def broadcast(self, message: str, *, exclude: Optional[str] = None) -> int:
        """Send *message* to all active connections, optionally excluding one *key*.

        When a ``WSRedisBridge`` is configured, also publishes to Redis.
        """
        sent = 0
        for key, conn in list(self._connections.items()):
            if key == exclude:
                continue
            try:
                await conn.websocket.send_text(message)
                sent += 1
                self._metrics.sent += 1
                if self._stats:
                    await self._stats.ws_sent(key)
            except Exception:
                self._metrics.failed += 1
                if self._stats:
                    await self._stats.ws_failed(key)
        logger.info(
            "ws.broadcast worker=%d sent=%d total=%d exclude=%s",
            _WORKER_ID, sent, len(self._connections), exclude,
        )
        self._publish_to_redis("broadcast", "", message, exclude=exclude)
        return sent

    # ------------------------------------------------------------------
    # Redis relay delivery
    # ------------------------------------------------------------------

    async def _deliver_from_redis(
        self, action: str, key: str, message: str, *, exclude: Optional[str] = None,
    ) -> None:
        """Deliver a message received from Redis to local connections.

        Never re-publishes to Redis — loop prevention is enforced by
        the bridge which only calls this method for incoming Redis messages.
        """
        logger.debug(
            "ws.redis_deliver action=%s key=%s worker=%d exclude=%s",
            action, key, _WORKER_ID, exclude,
        )
        if action == "send":
            conn = self._connections.get(key)
            if conn is not None:
                try:
                    await conn.websocket.send_text(message)
                    self._metrics.sent += 1
                    if self._stats:
                        await self._stats.ws_sent(key)
                except Exception:
                    self._metrics.failed += 1
                    if self._stats:
                        await self._stats.ws_failed(key)
                    self._queue_pending(key, message)
            else:
                self._queue_pending(key, message)
        elif action == "broadcast":
            for conn_key, conn in list(self._connections.items()):
                if conn_key == exclude:
                    continue
                try:
                    await conn.websocket.send_text(message)
                    self._metrics.sent += 1
                    if self._stats:
                        await self._stats.ws_sent(conn_key)
                except Exception:
                    self._metrics.failed += 1
                    if self._stats:
                        await self._stats.ws_failed(conn_key)

    def _publish_to_redis(
        self, action: str, key: str, message: str, *, exclude: Optional[str] = None,
    ) -> None:
        """Schedule a Redis publish via the bridge (fire-and-forget).

        Loop prevention: the bridge's ``publish()`` method adds the
        ``_broadcast_source`` marker to the Redis envelope, so incoming
        messages are never re-published.  No check on *message* content
        is needed here because ``_deliver_from_redis`` never calls this
        method — it delivers locally only.
        """
        if self._redis_bridge is None:
            return

        try:
            loop = asyncio.get_running_loop()
            loop.create_task(
                self._redis_bridge.publish(action, key, message, exclude=exclude),
                name="ws.redis_publish",
            )
        except RuntimeError:
            logger.warning("ws.redis_publish.no_event_loop worker=%d", _WORKER_ID)

    # ------------------------------------------------------------------
    # Message handling
    # ------------------------------------------------------------------

    async def handle_message(self, key: str, data: str) -> None:
        """Default inbound message handler — override in subclasses or ignore.

        Logs the message; applications should subclass or register custom handlers.
        """
        logger.debug("ws.message key=%s worker=%d len=%d", key, _WORKER_ID, len(data))

    # ------------------------------------------------------------------
    # Heartbeat / drain
    # ------------------------------------------------------------------

    async def heartbeat(self, key: str) -> None:
        """Mark *key* as alive and drain any pending messages."""
        conn = self._connections.get(key)
        if conn is None:
            return

        if self._stats:
            await self._stats.ws_heartbeat(key)

        await self._drain_pending(key, conn)

    # ------------------------------------------------------------------
    # Introspection / observability
    # ------------------------------------------------------------------

    @property
    def active_connections(self) -> dict[str, float]:
        """Return ``{key: connected_at_monotonic}`` for all active connections."""
        return {k: v.connected_at for k, v in self._connections.items()}

    @property
    def status(self) -> str:
        """Return ``"running"`` or ``"stopped"``."""
        return "running" if self._running else "stopped"

    @property
    def connection_count(self) -> int:
        """Number of currently active connections."""
        return len(self._connections)

    @property
    def bridge_stats(self) -> Optional[Dict[str, Any]]:
        """Redis bridge stats, or ``None`` if no bridge is configured."""
        if self._redis_bridge is not None:
            return self._redis_bridge.get_stats()
        return None

    def is_connected(self, key: str) -> bool:
        return key in self._connections

    def pending_count(self, key: str) -> int:
        conn = self._connections.get(key)
        if conn is not None:
            return len(conn.pending)
        buf = self._disconnected_pending.get(key)
        return len(buf) if buf is not None else 0

    def connection_info(self, key: str) -> Optional[Dict[str, Any]]:
        """Return observability metadata for *key*, or ``None`` if not connected."""
        conn = self._connections.get(key)
        if conn is None:
            return None
        return {
            "key": key,
            "worker_id": conn.worker_id,
            "connected_at": conn.connected_at,
            "pending_messages": len(conn.pending),
            "metadata": conn.metadata,
        }

    def all_connection_info(self) -> Dict[str, Dict[str, Any]]:
        """Return observability metadata for all active connections."""
        return {
            key: {
                "key": key,
                "worker_id": conn.worker_id,
                "connected_at": conn.connected_at,
                "pending_messages": len(conn.pending),
                "metadata": conn.metadata,
            }
            for key, conn in self._connections.items()
        }

    @property
    def metrics(self) -> Dict[str, int]:
        """Return aggregate counter snapshot."""
        m = self._metrics
        return {
            "opened": m.opened,
            "closed": m.closed,
            "sent": m.sent,
            "queued": m.queued,
            "failed": m.failed,
        }

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _queue_pending(self, key: str, message: str) -> None:
        conn = self._connections.get(key)
        if conn is not None:
            conn.pending.append(message)
        else:
            buf = self._disconnected_pending.setdefault(key, deque(maxlen=self._max_pending))
            buf.append(message)
        self._metrics.queued += 1

    async def _drain_pending(self, key: str, conn: _Connection) -> int:
        """Flush pending messages to *conn*.  Returns count drained."""
        drained = 0
        while conn.pending:
            msg = conn.pending.popleft()
            try:
                await conn.websocket.send_text(msg)
                drained += 1
                self._metrics.sent += 1
                if self._stats:
                    await self._stats.ws_sent(key)
            except Exception:
                conn.pending.appendleft(msg)
                self._metrics.failed += 1
                if self._stats:
                    await self._stats.ws_failed(key)
                break

        if self._stats:
            await self._stats.ws_pending(key, len(conn.pending))

        if drained:
            logger.info("ws.drained key=%s worker=%d messages=%d", key, _WORKER_ID, drained)
        return drained


@dataclass
class _ConnectionMetrics:
    """Simple counters for observability."""

    opened: int = 0
    closed: int = 0
    sent: int = 0
    queued: int = 0
    failed: int = 0