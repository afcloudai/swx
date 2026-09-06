"""
WebSocket Connection Manager
-----------------------------
Reliable connection management with:

* **Single-connection-per-key** — new connection replaces old.
* **Pending message queue** — 64-message per-key overflow buffer.
  Oldest messages are dropped when the queue is full.
* **drain_pending()** — on heartbeat/registration, queued messages
  are flushed to the reconnected client.
* **Metrics** — opened, closed, sent, queued, failed counters fed
  into ``StatsCollector``.

Typical usage in a FastAPI route::

    from swx_core.websocket import ConnectionManager

    ws_mgr = ConnectionManager()

    # Basic: let the manager accept the connection
    @router.websocket("/ws/{device_id}")
    async def ws_endpoint(websocket: WebSocket, device_id: str):
        await ws_mgr.connect(device_id, websocket)
        try:
            while True:
                data = await websocket.receive_text()
                await ws_mgr.handle_message(device_id, data)
        except WebSocketDisconnect:
            pass
        finally:
            await ws_mgr.disconnect(device_id)

    # Advanced: accept yourself (e.g. after auth) then pass accept=False
    @router.websocket("/ws/{device_id}")
    async def ws_endpoint(websocket: WebSocket, device_id: str):
        await websocket.accept()                     # accept early
        user = await authenticate(websocket)         # custom auth
        await ws_mgr.connect(device_id, websocket, accept=False)  # skip accept
        ...
"""

from __future__ import annotations

import logging
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Deque, Dict, Optional

from fastapi import WebSocket

from swx_core.realtime.stats import StatsCollector

logger = logging.getLogger(__name__)

_MAX_PENDING = 64


@dataclass
class _Connection:
    """Internal bookkeeping for a single WebSocket connection."""

    websocket: WebSocket
    connected_at: float = field(default_factory=time.monotonic)
    pending: Deque[str] = field(default_factory=lambda: deque(maxlen=_MAX_PENDING))


class ConnectionManager:
    """Framework-level WebSocket connection manager.

    Enforces one active connection per key.  When a new connection
    arrives for an existing key, the old one is replaced.  Disconnected
    keys accumulate pending messages that are drained on reconnect.
    """

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

    # ------------------------------------------------------------------
    # Connect / Disconnect
    # ------------------------------------------------------------------

    async def connect(self, key: str, websocket: WebSocket, *, accept: bool = True) -> None:
        """Register *websocket* under *key*.

        If *accept* is ``True`` (the default), ``await websocket.accept()`` is
        called before registration.  Pass ``accept=False`` when the caller has
        already accepted the WebSocket — for example, after authenticating the
        connection in an auth middleware.

        If a connection already exists for *key*, it is replaced (the old
        socket is closed).  Pending messages are drained to the new connection.
        """
        if accept:
            await websocket.accept()

        existing = self._connections.get(key)
        if existing is not None:
            logger.info("ws.replace key=%s (old connection replaced)", key)
            try:
                await existing.websocket.close()
            except Exception:
                pass

        conn = _Connection(websocket=websocket)
        self._connections[key] = conn

        # Transfer disconnected-pending messages to the new connection.
        pending = self._disconnected_pending.pop(key, None)
        if pending:
            for msg in pending:
                conn.pending.append(msg)

        self._metrics.opened += 1

        if self._stats:
            await self._stats.ws_connect(key)
            await self._stats.ws_heartbeat(key)

        # Drain pending messages from previous connection.
        await self._drain_pending(key, conn)

        logger.info("ws.connected key=%s total=%d", key, len(self._connections))

    async def disconnect(self, key: str) -> None:
        """Remove the connection for *key* (best-effort close).

        Pending messages on the connection are preserved in a
        disconnected-pending buffer so they can be drained on reconnect.
        """
        conn = self._connections.pop(key, None)
        if conn is None:
            return

        # Preserve any undrained pending messages for drain-on-reconnect.
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

        logger.info("ws.disconnected key=%s remaining=%d", key, len(self._connections))

    # ------------------------------------------------------------------
    # Send
    # ------------------------------------------------------------------

    async def send(self, key: str, message: str) -> bool:
        """Send *message* to the connection identified by *key*.

        If the connection is active, sends immediately.  Otherwise,
        queues the message for drain-on-reconnect.

        Returns ``True`` if sent immediately, ``False`` if queued.
        """
        conn = self._connections.get(key)

        if conn is not None:
            try:
                await conn.websocket.send_text(message)
                self._metrics.sent += 1
                if self._stats:
                    await self._stats.ws_sent(key)
                return True
            except Exception:
                logger.warning("ws.send_failed key=%s (will queue)", key)
                self._metrics.failed += 1
                if self._stats:
                    await self._stats.ws_failed(key)

        # Queue for later drain.
        self._queue_pending(key, message)
        return False

    async def broadcast(self, message: str, *, exclude: Optional[str] = None) -> int:
        """Send *message* to all active connections, optionally excluding one *key*."""
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
        return sent

    # ------------------------------------------------------------------
    # Message handling
    # ------------------------------------------------------------------

    async def handle_message(self, key: str, data: str) -> None:
        """Default inbound message handler — override in subclasses or ignore.

        Logs the message; applications should subclass or register custom handlers.
        """
        logger.debug("ws.message key=%s data=%s", key, data[:200])

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
    # Introspection
    # ------------------------------------------------------------------

    @property
    def active_connections(self) -> dict[str, float]:
        """Return ``{key: connected_at_monotonic}`` for all active connections."""
        return {k: v.connected_at for k, v in self._connections.items()}

    def is_connected(self, key: str) -> bool:
        return key in self._connections

    def pending_count(self, key: str) -> int:
        conn = self._connections.get(key)
        if conn is not None:
            return len(conn.pending)
        buf = self._disconnected_pending.get(key)
        return len(buf) if buf is not None else 0

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
                # Put it back and stop trying.
                conn.pending.appendleft(msg)
                self._metrics.failed += 1
                if self._stats:
                    await self._stats.ws_failed(key)
                break

        if self._stats:
            await self._stats.ws_pending(key, len(conn.pending))

        if drained:
            logger.info("ws.drained key=%s messages=%d", key, drained)
        return drained


@dataclass
class _ConnectionMetrics:
    """Simple counters for observability."""

    opened: int = 0
    closed: int = 0
    sent: int = 0
    queued: int = 0
    failed: int = 0