"""
SSE Event Store
---------------
Persists SSE events in Redis sorted sets for ``Last-Event-ID`` replay
across worker restarts.  Falls back to an in-process ring buffer when
Redis is unavailable.

Keys
~~~~~

* ``swx:sse:events:{channel}`` — Redis sorted set, score = monotonic
  event ID, value = JSON-encoded event payload.
* TTL of 5 minutes per key (auto-expired).

Ring buffer fallback
~~~~~~~~~~~~~~~~~~~~~

When Redis is unreachable, events are buffered in a fixed-size
``collections.deque`` per channel.  Replay is limited to events still
in the buffer — older events are lost on worker restart.  This is
acceptable for the vast majority of SaaS real-time feeds.
"""

from __future__ import annotations

import json
import logging
from collections import deque
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

_DEFAULT_TTL = 300  # 5 minutes
_RING_BUFFER_SIZE = 128


class SSEEventStore:
    """Persist SSE events for ``Last-Event-ID`` replay.

    Uses Redis sorted sets when available (cross-worker replay) and
    falls back to an in-process ring buffer otherwise.
    """

    def __init__(
        self,
        redis_client: Any = None,
        ttl: int = _DEFAULT_TTL,
        ring_size: int = _RING_BUFFER_SIZE,
    ) -> None:
        self._redis = redis_client
        self._ttl = ttl
        self._ring_size = ring_size
        self._buffers: Dict[str, deque[Tuple[int, str]]] = {}
        self._monotonic_id: int = 0

    @staticmethod
    def _key(channel: str) -> str:
        return f"swx:sse:events:{channel}"

    def next_id(self) -> int:
        """Return the next monotonic event ID (process-local)."""
        self._monotonic_id += 1
        return self._monotonic_id

    async def store(self, channel: str, event_id: int, data: Dict[str, Any]) -> None:
        """Persist an event for ``Last-Event-ID`` replay.

        Writes to Redis (best-effort) and always writes to the ring buffer.
        """
        serialized = json.dumps(data, default=str)
        self._ring_push(channel, event_id, serialized)

        if self._redis is None:
            return

        try:
            key = self._key(channel)
            pipe = self._redis.pipeline()
            pipe.zadd(key, {serialized: event_id})
            pipe.expire(key, self._ttl)
            await pipe.execute()
        except Exception:
            logger.debug("sse.store_failed channel=%s (ring buffer OK)", channel, exc_info=True)

    async def replay(self, channel: str, last_event_id: int) -> List[Dict[str, Any]]:
        """Return events newer than *last_event_id* for *channel*.

        Tries Redis first; falls back to the in-process ring buffer.
        """
        events = await self._replay_redis(channel, last_event_id)
        if events is not None:
            return events
        return self._replay_ring(channel, last_event_id)

    async def _replay_redis(self, channel: str, last_event_id: int) -> Optional[List[Dict[str, Any]]]:
        if self._redis is None:
            return None

        try:
            key = self._key(channel)
            raw_entries = await self._redis.zrangebyscore(key, f"({last_event_id}", "+inf")
            if raw_entries is None:
                return None
            return [json.loads(entry) for entry in raw_entries]
        except Exception:
            logger.debug("sse.replay_redis_failed channel=%s", channel, exc_info=True)
            return None

    def _replay_ring(self, channel: str, last_event_id: int) -> List[Dict[str, Any]]:
        buf = self._buffers.get(channel)
        if buf is None:
            return []
        results = []
        for eid, serialized in buf:
            if eid > last_event_id:
                try:
                    results.append(json.loads(serialized))
                except (json.JSONDecodeError, TypeError):
                    continue
        return results

    async def cleanup(self, channel: str) -> None:
        """Remove the channel's ring buffer.  Redis keys auto-expire via TTL."""
        self._buffers.pop(channel, None)

    # ------------------------------------------------------------------
    # Ring buffer internals
    # ------------------------------------------------------------------

    def _ring_push(self, channel: str, event_id: int, serialized: str) -> None:
        if channel not in self._buffers:
            self._buffers[channel] = deque(maxlen=self._ring_size)
        self._buffers[channel].append((event_id, serialized))