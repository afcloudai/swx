"""
SSE Redis Pub/Sub Bridge
------------------------
Bridges SSE broadcasts across multiple worker processes via Redis Pub/Sub.

Without this bridge, ``SSEManager.broadcast()`` only delivers to in-process
``asyncio.Queue`` subscribers — events published on worker 18 never reach
subscribers connected to worker 17.  This is the classic "works in dev
(1 worker), breaks in prod (N workers)" scenario.

The bridge works alongside the existing ``RedisEventBridge`` (which handles
EventBus→Redis fan-out).  SSE needs its own bridge because:

1. ``SSEManager.broadcast()`` is a *push* to in-process queues, not an
   EventBus event — so ``RedisEventBridge`` never sees it.
2. SSE delivery is *channel-scoped* (``orders:abc-123``), not *event-scoped*
   (``order.paid``).  The routing key is different.
3. ``SSEEventStore`` persists events for Last-Event-ID replay, but persistence
   alone cannot push to subscribers on other workers.

Architecture
~~~~~~~~~~~~~

* **Publish path**: ``SSEManager.broadcast()`` calls
  ``self._redis_bridge.publish(channel, data)`` after persisting the event.
  This publishes a JSON message to ``swx:sse:{channel}``.
* **Subscribe path**: ``SSERedisBridge._listen_loop()`` runs a background
  ``redis.asyncio.PubSub`` listener on ``swx:sse:*``.  When a message arrives
  from another worker, it calls ``SSEManager._deliver_from_redis(channel, data)``
  which pushes to local subscribers without re-persisting.
* **Loop prevention**: Messages published by this bridge carry a
  ``_broadcast_source="redis_sse"`` marker.  ``SSEManager.broadcast()`` skips
  the Redis publish when it sees this marker, preventing fan-out loops.

Usage (automatic via ``create_swx_app()``)::

    from swx_core.sse.manager import SSEManager
    from swx_core.sse.redis_bridge import SSERedisBridge

    sse = SSEManager.create(stats=stats)
    bridge = SSERedisBridge(sse_manager=sse, redis_client=redis)
    await bridge.start()

    # SSEManager.broadcast() now reaches all workers.
    await sse.broadcast("orders:abc-123", {"type": "order.paid", "order_id": "abc-123"})
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import Any, Dict, Optional

from swx_core.sse.manager import SSEManager

logger = logging.getLogger(__name__)

SOURCE_META_KEY = "_broadcast_source"
SOURCE_REDIS_SSE = "redis_sse"


class SSERedisBridge:
    """Bridges ``SSEManager.broadcast()`` across worker processes via Redis Pub/Sub.

    * **Publish**: called by ``SSEManager.broadcast()`` to fan out to other workers.
    * **Subscribe**: background task receives messages from other workers and
      delivers them locally via ``SSEManager._deliver_from_redis()``.
    """

    RECONNECT_DELAY = 5.0
    MAX_RECONNECT_ATTEMPTS: Optional[int] = None

    def __init__(
        self,
        sse_manager: SSEManager,
        redis_client: Any = None,
        channel_prefix: str = "swx:sse",
    ) -> None:
        self._sse = sse_manager
        self._redis = redis_client
        self._channel_prefix = channel_prefix
        self._pubsub: Any = None
        self._listener_task: Optional[asyncio.Task[None]] = None
        self._running = False
        self._reconnect_attempts = 0

    @property
    def is_running(self) -> bool:
        return self._running

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        """Start the background Redis subscriber task."""
        if self._redis is None:
            logger.warning("sse.redis_bridge.not_started no Redis client — SSE stays in-process")
            return

        if self._running:
            return

        self._running = True
        self._reconnect_attempts = 0

        self._pubsub = self._redis.pubsub()
        pattern = f"{self._channel_prefix}:*"
        await self._pubsub.psubscribe(pattern)
        logger.info("sse.redis_bridge.subscribed pattern=%s", pattern)

        self._listener_task = asyncio.create_task(self._listen_loop())
        logger.info("sse.redis_bridge.started")

    async def stop(self) -> None:
        """Stop the background Redis subscriber task gracefully."""
        self._running = False

        if self._listener_task is not None:
            self._listener_task.cancel()
            try:
                await self._listener_task
            except asyncio.CancelledError:
                pass
            self._listener_task = None

        if self._pubsub is not None:
            try:
                await self._pubsub.unsubscribe()
                await self._pubsub.punsubscribe()
                await self._pubsub.close()
            except Exception as exc:
                logger.debug("sse.redis_bridge.close_error %s", exc)
            self._pubsub = None

        logger.info("sse.redis_bridge.stopped")

    # ------------------------------------------------------------------
    # Publish
    # ------------------------------------------------------------------

    async def publish(self, channel: str, data: Dict[str, Any]) -> None:
        """Publish an SSE event to Redis for cross-worker delivery.

        Called by ``SSEManager.broadcast()`` after local delivery and
        persistence.  Other workers' ``_listen_loop()`` will pick it up.
        """
        if self._redis is None:
            return

        message = {
            "channel": channel,
            "data": data,
            "ts": time.time(),
        }

        redis_channel = f"{self._channel_prefix}:{channel}"
        try:
            serialized = json.dumps(message, default=str)
            await self._redis.publish(redis_channel, serialized)
            logger.debug("sse.redis_bridge.published channel=%s", channel)
        except Exception as exc:
            logger.warning("sse.redis_bridge.publish_failed channel=%s %s", channel, exc)

    # ------------------------------------------------------------------
    # Internal: listener loop
    # ------------------------------------------------------------------

    async def _listen_loop(self) -> None:
        if self._pubsub is None:
            return

        try:
            while self._running:
                pubsub = self._pubsub
                if pubsub is None:
                    break
                try:
                    message = await pubsub.get_message(
                        ignore_subscribe_messages=True,
                        timeout=1.0,
                    )
                    if message and message["type"] == "pmessage":
                        await self._handle_message(message)
                except asyncio.CancelledError:
                    raise
                except Exception as exc:
                    logger.error("sse.redis_bridge.listen_error %s", exc)
                    self._reconnect_attempts += 1
                    if (
                        self.MAX_RECONNECT_ATTEMPTS is not None
                        and self._reconnect_attempts >= self.MAX_RECONNECT_ATTEMPTS
                    ):
                        logger.critical("sse.redis_bridge.max_reconnect_attempts exceeded")
                        self._running = False
                        break
                    logger.info(
                        "sse.redis_bridge.reconnecting in %ss (attempt %d)",
                        self.RECONNECT_DELAY,
                        self._reconnect_attempts,
                    )
                    await asyncio.sleep(self.RECONNECT_DELAY)
                    try:
                        if self._pubsub is not None:
                            await self._pubsub.close()
                        self._pubsub = self._redis.pubsub()
                        pattern = f"{self._channel_prefix}:*"
                        await self._pubsub.psubscribe(pattern)
                        self._reconnect_attempts = 0
                        logger.info("sse.redis_bridge.reconnected")
                    except Exception as reconnect_exc:
                        logger.error("sse.redis_bridge.reconnect_failed %s", reconnect_exc)
        except asyncio.CancelledError:
            logger.debug("sse.redis_bridge.listener_cancelled")
        except Exception as exc:
            logger.critical("sse.redis_bridge.listener_crashed %s", exc)

    async def _handle_message(self, message: Dict[str, Any]) -> None:
        try:
            data = json.loads(message["data"])
            channel = data.get("channel")
            event_data = data.get("data")

            if not channel or not event_data:
                logger.warning("sse.redis_bridge.malformed_message channel=%s", channel)
                return

            await self._sse._deliver_from_redis(channel, event_data)
            logger.debug("sse.redis_bridge.delivered channel=%s", channel)
        except (json.JSONDecodeError, KeyError, TypeError) as exc:
            logger.warning("sse.redis_bridge.parse_error %s", exc)

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_stats(self) -> Dict[str, Any]:
        return {
            "running": self._running,
            "redis_connected": self._redis is not None,
            "channel_prefix": self._channel_prefix,
            "reconnect_attempts": self._reconnect_attempts,
        }