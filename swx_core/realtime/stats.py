"""
Real-time Stats Collector
--------------------------
Aggregates per-channel, per-listener, and per-connection metrics from
SSEManager and ConnectionManager.  Exposes a ``health_check`` callback
suitable for ``HealthChecker.add_check("realtime", ...)``.

Design notes
~~~~~~~~~~~~~

* **Lock-free reads**: counters are plain ints incremented under a single
  ``asyncio.Lock``.  Reads snapshot without locking — acceptable for
  monitoring counters where slight staleness is fine.
* **No external deps**: pure-stdlib + ``swx_core`` internals only.
* **Framework primitive**: instantiated once in ``app_factory`` and shared
  across SSE and WS managers.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any, Dict, Optional

from swx_core.utils.time import utc_now
from swx_core.utils.health import HealthStatus


@dataclass
class ChannelStats:
    """Metrics for a single SSE channel (e.g. ``"orders:abc-123"``)."""

    subscribers: int = 0
    delivered: int = 0
    evicted: int = 0
    last_event_at: Optional[str] = None


@dataclass
class ListenerStats:
    """Metrics for an EventBus→SSE/WS bridge listener."""

    events_received: int = 0
    events_forwarded: int = 0
    errors: int = 0


@dataclass
class ConnectionStats:
    """Metrics for a single WebSocket connection key (e.g. ``"kiosk-42"``)."""

    connected: bool = False
    pending_messages: int = 0
    last_heartbeat_at: Optional[str] = None


class StatsCollector:
    """Centralised observability for real-time connections.

    SSEManager and ConnectionManager call into the collector on every
    meaningful event (subscribe, broadcast, disconnect, …).  The
    ``snapshot()`` method returns a JSON-friendly dict for ``/health`` and
    admin dashboards.  ``health_check()`` is an async callable compatible
    with ``HealthChecker.add_check()``.
    """

    def __init__(self) -> None:
        self._lock = asyncio.Lock()

        # --- SSE channel-level ---
        self._channel_subscribers: Dict[str, int] = {}
        self._channel_delivered: Dict[str, int] = {}
        self._channel_evicted: Dict[str, int] = {}
        self._channel_last_event: Dict[str, str] = {}

        # --- SSE aggregate ---
        self._sse_total_subscriptions: int = 0
        self._sse_total_delivered: int = 0
        self._sse_total_evicted: int = 0

        # --- WS connection-level ---
        self._ws_connected: Dict[str, bool] = {}
        self._ws_pending: Dict[str, int] = {}
        self._ws_last_heartbeat: Dict[str, str] = {}
        self._ws_sent: Dict[str, int] = {}
        self._ws_failed: Dict[str, int] = {}

        # --- WS aggregate ---
        self._ws_total_connections: int = 0
        self._ws_total_sent: int = 0
        self._ws_total_failed: int = 0

        # --- Bridge listener-level ---
        self._listener_received: Dict[str, int] = {}
        self._listener_forwarded: Dict[str, int] = {}
        self._listener_errors: Dict[str, int] = {}

    # ------------------------------------------------------------------
    # SSE metrics
    # ------------------------------------------------------------------

    async def sse_subscribe(self, channel: str) -> None:
        async with self._lock:
            self._channel_subscribers[channel] = self._channel_subscribers.get(channel, 0) + 1
            self._sse_total_subscriptions += 1

    async def sse_unsubscribe(self, channel: str) -> None:
        async with self._lock:
            current = self._channel_subscribers.get(channel, 0)
            if current > 0:
                self._channel_subscribers[channel] = current - 1
            self._sse_total_subscriptions = max(0, self._sse_total_subscriptions - 1)

    async def sse_delivered(self, channel: str) -> None:
        async with self._lock:
            self._channel_delivered[channel] = self._channel_delivered.get(channel, 0) + 1
            self._channel_last_event[channel] = utc_now().isoformat()
            self._sse_total_delivered += 1

    async def sse_evicted(self, channel: str) -> None:
        async with self._lock:
            self._channel_evicted[channel] = self._channel_evicted.get(channel, 0) + 1
            self._sse_total_evicted += 1

    async def sse_channel_remove(self, channel: str) -> None:
        async with self._lock:
            self._channel_subscribers.pop(channel, None)
            self._channel_delivered.pop(channel, None)
            self._channel_evicted.pop(channel, None)
            self._channel_last_event.pop(channel, None)

    # ------------------------------------------------------------------
    # WS metrics
    # ------------------------------------------------------------------

    async def ws_connect(self, key: str) -> None:
        async with self._lock:
            self._ws_connected[key] = True
            self._ws_pending[key] = self._ws_pending.get(key, 0)
            self._ws_total_connections += 1

    async def ws_disconnect(self, key: str) -> None:
        async with self._lock:
            self._ws_connected[key] = False
            self._ws_total_connections = max(0, self._ws_total_connections - 1)

    async def ws_sent(self, key: str) -> None:
        async with self._lock:
            self._ws_sent[key] = self._ws_sent.get(key, 0) + 1
            self._ws_total_sent += 1

    async def ws_failed(self, key: str) -> None:
        async with self._lock:
            self._ws_failed[key] = self._ws_failed.get(key, 0) + 1
            self._ws_total_failed += 1

    async def ws_pending(self, key: str, count: int) -> None:
        async with self._lock:
            self._ws_pending[key] = count

    async def ws_heartbeat(self, key: str) -> None:
        async with self._lock:
            self._ws_last_heartbeat[key] = utc_now().isoformat()

    async def ws_remove(self, key: str) -> None:
        async with self._lock:
            self._ws_connected.pop(key, None)
            self._ws_pending.pop(key, None)
            self._ws_last_heartbeat.pop(key, None)
            self._ws_sent.pop(key, None)
            self._ws_failed.pop(key, None)

    # ------------------------------------------------------------------
    # Stale entry cleanup
    # ------------------------------------------------------------------

    async def cleanup_stale(self) -> None:
        """Remove entries for disconnected channels and connections.

        Call periodically (e.g. from a keepalive or health-check loop)
        to prevent unbounded memory growth from transient channels.
        """
        async with self._lock:
            stale_channels = [
                ch for ch, subs in self._channel_subscribers.items()
                if subs == 0
            ]
            for ch in stale_channels:
                self._channel_subscribers.pop(ch, None)
                self._channel_delivered.pop(ch, None)
                self._channel_evicted.pop(ch, None)
                self._channel_last_event.pop(ch, None)

            stale_ws = [
                key for key, connected in self._ws_connected.items()
                if not connected
            ]
            for key in stale_ws:
                self._ws_connected.pop(key, None)
                self._ws_pending.pop(key, None)
                self._ws_last_heartbeat.pop(key, None)
                self._ws_sent.pop(key, None)
                self._ws_failed.pop(key, None)

    # ------------------------------------------------------------------
    # Bridge listener metrics
    # ------------------------------------------------------------------

    async def listener_received(self, name: str) -> None:
        async with self._lock:
            self._listener_received[name] = self._listener_received.get(name, 0) + 1

    async def listener_forwarded(self, name: str) -> None:
        async with self._lock:
            self._listener_forwarded[name] = self._listener_forwarded.get(name, 0) + 1

    async def listener_error(self, name: str) -> None:
        async with self._lock:
            self._listener_errors[name] = self._listener_errors.get(name, 0) + 1

    # ------------------------------------------------------------------
    # Snapshot (for dashboards / health endpoint)
    # ------------------------------------------------------------------

    async def snapshot(self) -> Dict[str, Any]:
        """Return a full metrics snapshot (safe for JSON serialisation)."""
        async with self._lock:
            channels: Dict[str, Dict[str, Any]] = {}
            for ch in sorted(set(self._channel_subscribers) | set(self._channel_delivered) | set(self._channel_evicted)):
                channels[ch] = {
                    "subscribers": self._channel_subscribers.get(ch, 0),
                    "delivered": self._channel_delivered.get(ch, 0),
                    "evicted": self._channel_evicted.get(ch, 0),
                    "last_event_at": self._channel_last_event.get(ch),
                }

            listeners: Dict[str, Dict[str, Any]] = {}
            for name in sorted(set(self._listener_received) | set(self._listener_forwarded) | set(self._listener_errors)):
                listeners[name] = {
                    "events_received": self._listener_received.get(name, 0),
                    "events_forwarded": self._listener_forwarded.get(name, 0),
                    "errors": self._listener_errors.get(name, 0),
                }

            ws_conns: Dict[str, Dict[str, Any]] = {}
            for key in sorted(set(self._ws_connected) | set(self._ws_pending) | set(self._ws_sent)):
                ws_conns[key] = {
                    "connected": self._ws_connected.get(key, False),
                    "pending_messages": self._ws_pending.get(key, 0),
                    "last_heartbeat_at": self._ws_last_heartbeat.get(key),
                }

            return {
                "channels": channels,
                "listeners": listeners,
                "ws_connections": ws_conns,
                "aggregate": {
                    "sse_total_subscriptions": self._sse_total_subscriptions,
                    "sse_total_delivered": self._sse_total_delivered,
                    "sse_total_evicted": self._sse_total_evicted,
                    "ws_total_connections": self._ws_total_connections,
                    "ws_total_pending": sum(self._ws_pending.values()),
                    "ws_total_sent": self._ws_total_sent,
                    "ws_total_failed": self._ws_total_failed,
                },
            }

    # ------------------------------------------------------------------
    # Health check (for HealthChecker.add_check)
    # ------------------------------------------------------------------

    async def health_check(self) -> HealthStatus:
        """Async health-check callable for ``HealthChecker.add_check()``.

        Returns ``"degraded"`` when:
        * Any channel has active subscribers but zero deliveries (stale).
        * Any WS connection has >0 pending messages accumulating.
        * Any bridge listener has more errors than 10% of forwarded events.

        Returns ``"unhealthy"`` when:
        * Total WS pending exceeds total WS connections (system can't drain).
        """
        snap = await self.snapshot()
        aggregate = snap["aggregate"]
        channels = snap["channels"]
        ws_conns = snap["ws_connections"]
        listeners = snap["listeners"]

        degraded_reasons: list[str] = []
        unhealthy_reasons: list[str] = []

        # SSE: active subscribers with zero deliveries → likely broken
        for ch, stats in channels.items():
            if stats["subscribers"] > 0 and stats["delivered"] == 0:
                degraded_reasons.append(f"Channel {ch!r}: subscribers={stats['subscribers']} but delivered=0")

        # SSE: evictions climbing
        if aggregate["sse_total_evicted"] > 0:
            total = aggregate["sse_total_delivered"] + aggregate["sse_total_evicted"]
            evict_pct = (aggregate["sse_total_evicted"] / total * 100) if total else 0
            if evict_pct > 5:
                degraded_reasons.append(f"SSE eviction rate {evict_pct:.1f}% exceeds 5%")

        # WS: pending messages accumulating
        for key, stats in ws_conns.items():
            if stats["pending_messages"] > 0 and not stats["connected"]:
                degraded_reasons.append(f"WS {key!r}: {stats['pending_messages']} pending, disconnected")

        # WS: total pending > total connections (drain failure)
        total_pending = aggregate["ws_total_pending"]
        total_conns = aggregate["ws_total_connections"]
        if total_conns > 0 and total_pending > total_conns:
            unhealthy_reasons.append(f"WS pending ({total_pending}) exceeds connections ({total_conns})")

        # Bridge: high error rate
        for name, stats in listeners.items():
            if stats["events_forwarded"] > 0:
                error_pct = stats["errors"] / stats["events_forwarded"] * 100
                if error_pct > 10:
                    degraded_reasons.append(f"Listener {name!r}: error rate {error_pct:.1f}%")

        if unhealthy_reasons:
            return HealthStatus(
                name="realtime",
                status="unhealthy",
                message="; ".join(unhealthy_reasons),
                details=snap,
            )

        if degraded_reasons:
            return HealthStatus(
                name="realtime",
                status="degraded",
                message="; ".join(degraded_reasons),
                details=snap,
            )

        return HealthStatus(
            name="realtime",
            status="healthy",
            message="All real-time connections nominal",
            details=aggregate,
        )