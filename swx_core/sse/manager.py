"""
SSE Manager
-----------
Manages Server-Sent Events connections: subscribe by channel, broadcast
events with monotonic IDs, periodic keepalive pings, and automatic
cleanup on disconnect.

Typical usage::

    from swx_core.sse import SSEManager, SSEEventStore

    sse = SSEManager(event_store=SSEEventStore(redis_client=redis))

    # In a FastAPI route:
    @router.get("/events/{channel}")
    async def sse_endpoint(channel: str, request: Request):
        return StreamingResponse(
            sse.subscribe(channel, request),
            media_type="text/event-stream",
        )

    # Broadcasting:
    await sse.broadcast("orders:abc-123", {"type": "order.paid", "order_id": "abc-123"})

The manager tracks subscriptions in ``{channel: [queue, …]}`` format.
Each subscriber gets an ``asyncio.Queue``; the ``subscribe()`` method
returns an async generator that yields SSE-formatted frames.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any, AsyncIterator, Dict, List, Optional, Set

from swx_core.sse.event_store import SSEEventStore
from swx_core.realtime.stats import StatsCollector

logger = logging.getLogger(__name__)

_KEEPALIVE_INTERVAL = 15  # seconds

SOURCE_META_KEY = "_broadcast_source"
SOURCE_REDIS_SSE = "redis_sse"


@dataclass
class _Subscriber:
    """Internal bookkeeping for one SSE client connection."""

    queue: asyncio.Queue[Optional[str]]
    channel: str
    created_at: float = field(default_factory=time.monotonic)


class SSEManager:
    """Framework-level SSE connection manager.

    * **subscribe(channel, request)** → ``AsyncIterator[str]`` yielding
      SSE frames (``data: …\\n\\n``).  Supports ``Last-Event-ID``
      replay via the event store.
    * **broadcast(channel, data)** → pushes to all subscribers on
      *channel*, persists the event for replay.
    * **keepalive** task sends ``:keepalive\\n\\n`` comments every
      ``keepalive_interval`` seconds.
    """

    _instance: Optional["SSEManager"] = None

    def __init__(
        self,
        event_store: Optional[SSEEventStore] = None,
        stats: Optional[StatsCollector] = None,
        keepalive_interval: int = _KEEPALIVE_INTERVAL,
        redis_bridge: Any = None,
    ) -> None:
        self._store = event_store or SSEEventStore()
        self._stats = stats
        self._keepalive_interval = keepalive_interval
        self._redis_bridge = redis_bridge

        self._subscribers: Dict[str, List[_Subscriber]] = {}
        self._subscriber_count: int = 0
        self._keepalive_task: Optional[asyncio.Task[None]] = None
        self._running = False
        self._lock = asyncio.Lock()

    @classmethod
    def get_instance(cls) -> Optional["SSEManager"]:
        """Return the global SSEManager instance (or ``None`` if not created)."""
        return cls._instance

    @classmethod
    def create(
        cls,
        event_store: Optional[SSEEventStore] = None,
        stats: Optional[StatsCollector] = None,
        keepalive_interval: int = _KEEPALIVE_INTERVAL,
        redis_bridge: Any = None,
    ) -> "SSEManager":
        """Create and register the global singleton instance."""
        cls._instance = cls(event_store=event_store, stats=stats, keepalive_interval=keepalive_interval, redis_bridge=redis_bridge)
        return cls._instance

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._keepalive_task = asyncio.create_task(self._keepalive_loop())
        logger.info("sse.started")

    async def stop(self) -> None:
        self._running = False
        if self._keepalive_task is not None:
            self._keepalive_task.cancel()
            try:
                await self._keepalive_task
            except asyncio.CancelledError:
                pass
            self._keepalive_task = None

        for subs in self._subscribers.values():
            for sub in subs:
                await sub.queue.put(None)
        self._subscribers.clear()
        self._subscriber_count = 0
        logger.info("sse.stopped")

    # ------------------------------------------------------------------
    # Subscribe
    # ------------------------------------------------------------------

    async def subscribe(
        self,
        channel: str,
        last_event_id: Optional[int] = None,
    ) -> AsyncIterator[str]:
        """Yield SSE frames for *channel* until the client disconnects.

        If *last_event_id* is provided, replay missed events from the
        event store before streaming live events.
        """
        sub = _Subscriber(queue=asyncio.Queue(maxsize=256), channel=channel)
        async with self._lock:
            self._subscribers.setdefault(channel, []).append(sub)
            self._subscriber_count += 1

        if self._stats:
            await self._stats.sse_subscribe(channel)

        logger.info("sse.subscribe channel=%s subscribers=%d", channel, len(self._subscribers[channel]))

        # Replay missed events if Last-Event-ID is provided.
        if last_event_id is not None:
            replayed = await self._store.replay(channel, last_event_id)
            for event_data in replayed:
                await sub.queue.put(self._format_event(event_data))

        try:
            while self._running:
                frame = await asyncio.wait_for(sub.queue.get(), timeout=60.0)
                if frame is None:
                    break
                yield frame
        except asyncio.TimeoutError:
            # Client is still connected but idle; loop back.
            pass
        except asyncio.CancelledError:
            pass
        finally:
            await self._remove_subscriber(channel, sub)

    # ------------------------------------------------------------------
    # Broadcast
    # ------------------------------------------------------------------

    async def broadcast(self, channel: str, data: Dict[str, Any]) -> int:
        """Push *data* to all subscribers on *channel*.

        Persists the event for Last-Event-ID replay, delivers to local
        subscribers, and publishes to Redis for cross-worker delivery
        (when the SSE Redis bridge is configured).

        Returns the number of local subscribers that received the event
        (or were skipped because their queue was full).
        """
        if not channel:
            logger.warning("sse.broadcast_skipped reason=empty_channel")
            return 0

        # Events arriving from Redis must not be re-published (loop prevention).
        from_redis = data.get(SOURCE_META_KEY) == SOURCE_REDIS_SSE
        if from_redis:
            data = {k: v for k, v in data.items() if k != SOURCE_META_KEY}

        event_id = self._store.next_id()
        event_frame = {"id": event_id, "channel": channel, **data}

        # Persist for Last-Event-ID replay.
        await self._store.store(channel, event_id, event_frame)

        frame = self._format_event(event_frame)
        delivered = await self._push_to_local_subscribers(channel, frame)

        # Fan out to other workers via Redis (only for locally-originated events).
        if self._redis_bridge is not None and not from_redis:
            await self._redis_bridge.publish(channel, event_frame)

        logger.debug("sse.broadcast channel=%s event_id=%s delivered=%d", channel, event_id, delivered)
        return delivered

    async def _push_to_local_subscribers(self, channel: str, frame: str) -> int:
        """Push a pre-formatted SSE frame to all local subscribers on *channel*.

        Returns the number of subscribers that received the event.
        """
        delivered = 0
        for sub in list(self._subscribers.get(channel, [])):
            try:
                sub.queue.put_nowait(frame)
                delivered += 1
                if self._stats:
                    await self._stats.sse_delivered(channel)
            except asyncio.QueueFull:
                if self._stats:
                    await self._stats.sse_evicted(channel)
                logger.warning("sse.queue_full channel=%s subscriber_dropped", channel)
        return delivered

    async def _deliver_from_redis(self, channel: str, event_data: Dict[str, Any]) -> int:
        """Deliver an event received from Redis to local subscribers.

        Does NOT re-persist — the originating worker already stored it.
        Does NOT re-publish to Redis — the ``SOURCE_META_KEY`` marker in
        ``event_data`` is only used internally and stripped before framing.
        """
        clean_data = {k: v for k, v in event_data.items() if k != SOURCE_META_KEY}
        frame = self._format_event(clean_data)
        return await self._push_to_local_subscribers(channel, frame)

    # ------------------------------------------------------------------
    # Cleanup
    # ------------------------------------------------------------------

    async def _remove_subscriber(self, channel: str, sub: _Subscriber) -> None:
        async with self._lock:
            subs = self._subscribers.get(channel, [])
            if sub in subs:
                subs.remove(sub)
            self._subscriber_count = max(0, self._subscriber_count - 1)

        if self._stats:
            await self._stats.sse_unsubscribe(channel)

        async with self._lock:
            subs = self._subscribers.get(channel, [])
            if not subs:
                self._subscribers.pop(channel, None)

        await self._store.cleanup(channel)
        logger.info("sse.unsubscribe channel=%s remaining=%d", channel, len(self._subscribers.get(channel, [])))

    # ------------------------------------------------------------------
    # Keepalive
    # ------------------------------------------------------------------

    async def _keepalive_loop(self) -> None:
        try:
            while self._running:
                await asyncio.sleep(self._keepalive_interval)
                for channel, subs in list(self._subscribers.items()):
                    for sub in subs:
                        try:
                            sub.queue.put_nowait(": keepalive\n\n")
                        except asyncio.QueueFull:
                            pass
        except asyncio.CancelledError:
            pass

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _format_event(data: Dict[str, Any]) -> str:
        """Format an event dict into an SSE frame string.

        Uses ``id`` from *data* if present (set during broadcast).
        Falls back to serialising the entire dict as ``data:``.

        Per the SSE specification (W3C), each ``data:`` field must
        appear on its own line.  If the serialised payload contains
        newlines, it is split across multiple ``data:`` lines.
        """
        lines: list[str] = []
        if "id" in data:
            lines.append(f"id: {data['id']}")
        if "event" in data:
            lines.append(f"event: {data['event']}")
        payload_json = json.dumps({k: v for k, v in data.items() if k != "id"}, default=str)
        for line in payload_json.split("\n"):
            lines.append(f"data: {line}")
        lines.append("")
        lines.append("")
        return "\n".join(lines)

    @property
    def subscriber_count(self) -> int:
        return self._subscriber_count

    @property
    def channels(self) -> Set[str]:
        return set(self._subscribers.keys())