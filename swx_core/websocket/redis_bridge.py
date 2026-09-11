"""
WebSocket Redis Pub/Sub Bridge
------------------------------
Bridges WebSocket ``send`` and ``broadcast`` calls across multiple worker
processes via Redis Pub/Sub.

Without this bridge, ``ConnectionManager.send()`` and ``ConnectionManager.broadcast()``
only reach connections on the same worker — messages published on worker 3 never
reach clients connected to worker 7.  This is the classic "works in dev (1 worker),
breaks in prod (N workers)" scenario.

The bridge mirrors the SSE Redis bridge architecture:

* **Publish path**: ``ConnectionManager.send()`` / ``broadcast()`` calls
  ``_publish_to_redis()`` which schedules ``WSRedisBridge.publish()``.
  This publishes a JSON envelope to ``swx:ws:{action}``.
* **Subscribe path**: ``WSRedisBridge._listen_loop()`` runs a background
  ``redis.asyncio.PubSub`` listener on ``swx:ws:*``.  When a message arrives
  from another worker, it calls
  ``ConnectionManager._deliver_from_redis()`` which pushes to local
  connections without re-publishing.
* **Loop prevention**: Messages published by this bridge carry a
  ``_broadcast_source="redis_ws"`` marker in the envelope.  Since
  ``_deliver_from_redis`` never calls ``_publish_to_redis``, there is
  no re-publish path and no fan-out loop.

Usage (automatic via ``create_swx_app()``)::

    from swx_core.websocket.manager import ConnectionManager
    from swx_core.websocket.redis_bridge import WSRedisBridge

    ws_mgr = ConnectionManager.create(stats=stats)
    bridge = WSRedisBridge(ws_manager=ws_mgr, redis_client=redis)
    await bridge.start()

    # ConnectionManager.send() / broadcast() now reach all workers.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from typing import Any, Dict, Optional

from swx_core.websocket.manager import ConnectionManager, SOURCE_META_KEY, SOURCE_REDIS_WS

logger = logging.getLogger(__name__)

_WORKER_ID = os.getpid()


class WSRedisBridge:
    """Bridges ``ConnectionManager.send/broadcast`` across worker processes via Redis Pub/Sub.

    * **Publish**: called by ``ConnectionManager._publish_to_redis()`` to fan
      out to other workers.
    * **Subscribe**: background task receives messages from other workers and
      delivers them locally via ``ConnectionManager._deliver_from_redis()``.
    """

    RECONNECT_DELAY = 5.0
    MAX_RECONNECT_ATTEMPTS: Optional[int] = None

    def __init__(
        self,
        ws_manager: ConnectionManager,
        redis_client: Any = None,
        channel_prefix: str = "swx:ws",
    ) -> None:
        self._ws = ws_manager
        self._redis = redis_client
        self._channel_prefix = channel_prefix
        self._pubsub: Any = None
        self._listener_task: Optional[asyncio.Task[None]] = None
        self._running = False
        self._reconnect_attempts = 0
        self._messages_relayed = 0
        self._messages_published = 0

    @property
    def is_running(self) -> bool:
        return self._running

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        """Start the background Redis subscriber task."""
        if self._redis is None:
            logger.warning("ws.redis_bridge.not_started worker=%d no Redis client — WS stays in-process", _WORKER_ID)
            return

        if self._running:
            return

        self._running = True
        self._reconnect_attempts = 0

        self._pubsub = self._redis.pubsub()
        pattern = f"{self._channel_prefix}:*"
        await self._pubsub.psubscribe(pattern)
        logger.info("ws.redis_bridge.subscribed pattern=%s worker=%d", pattern, _WORKER_ID)

        self._listener_task = asyncio.create_task(self._listen_loop())
        logger.info("ws.redis_bridge.started worker=%d", _WORKER_ID)

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
                logger.debug("ws.redis_bridge.close_error worker=%d %s", _WORKER_ID, exc)
            self._pubsub = None

        logger.info("ws.redis_bridge.stopped worker=%d", _WORKER_ID)

    # ------------------------------------------------------------------
    # Publish
    # ------------------------------------------------------------------

    async def publish(
        self,
        action: str,
        key: str,
        message: str,
        *,
        exclude: Optional[str] = None,
    ) -> None:
        """Publish a WebSocket send/broadcast event to Redis for cross-worker delivery.

        The envelope includes ``_broadcast_source="redis_ws"`` for loop
        prevention and ``worker_id`` for observability.
        """
        if self._redis is None:
            return

        if not action:
            logger.warning("ws.redis_bridge.publish_skipped reason=empty_action worker=%d", _WORKER_ID)
            return

        payload: Dict[str, Any] = {
            "action": action,
            "key": key,
            "message": message,
            "exclude": exclude,
            SOURCE_META_KEY: SOURCE_REDIS_WS,
            "worker_id": _WORKER_ID,
            "ts": time.time(),
        }

        redis_channel = f"{self._channel_prefix}:{action}"
        try:
            serialized = json.dumps(payload, default=str)
            await self._redis.publish(redis_channel, serialized)
            self._messages_published += 1
            logger.debug(
                "ws.redis_bridge.published action=%s key=%s worker=%d",
                action, key, _WORKER_ID,
            )
        except Exception as exc:
            logger.warning(
                "ws.redis_bridge.publish_failed action=%s key=%s worker=%d %s",
                action, key, _WORKER_ID, exc,
            )

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
                    logger.error("ws.redis_bridge.listen_error worker=%d %s", _WORKER_ID, exc)
                    self._reconnect_attempts += 1
                    if (
                        self.MAX_RECONNECT_ATTEMPTS is not None
                        and self._reconnect_attempts >= self.MAX_RECONNECT_ATTEMPTS
                    ):
                        logger.critical("ws.redis_bridge.max_reconnect_attempts exceeded worker=%d", _WORKER_ID)
                        self._running = False
                        break
                    logger.info(
                        "ws.redis_bridge.reconnecting in %ss (attempt %d) worker=%d",
                        self.RECONNECT_DELAY, self._reconnect_attempts, _WORKER_ID,
                    )
                    await asyncio.sleep(self.RECONNECT_DELAY)
                    try:
                        if self._pubsub is not None:
                            await self._pubsub.close()
                        self._pubsub = self._redis.pubsub()
                        pattern = f"{self._channel_prefix}:*"
                        await self._pubsub.psubscribe(pattern)
                        self._reconnect_attempts = 0
                        logger.info("ws.redis_bridge.reconnected worker=%d", _WORKER_ID)
                    except Exception as reconnect_exc:
                        logger.error("ws.redis_bridge.reconnect_failed worker=%d %s", _WORKER_ID, reconnect_exc)
        except asyncio.CancelledError:
            logger.debug("ws.redis_bridge.listener_cancelled worker=%d", _WORKER_ID)
        except Exception as exc:
            logger.critical("ws.redis_bridge.listener_crashed worker=%d %s", _WORKER_ID, exc)

    async def _handle_message(self, message: Dict[str, Any]) -> None:
        try:
            data = json.loads(message["data"])
            action = data.get("action")
            key = data.get("key", "")
            msg = data.get("message", "")
            exclude = data.get("exclude")
            source_worker = data.get("worker_id")

            if not action or not msg:
                logger.warning("ws.redis_bridge.malformed_message action=%s has_msg=%s worker=%d", action, bool(msg), _WORKER_ID)
                return

            if action == "send" and not key:
                logger.warning("ws.redis_bridge.malformed_send reason=empty_key worker=%d", _WORKER_ID)
                return

            await self._ws._deliver_from_redis(action, key, msg, exclude=exclude)
            self._messages_relayed += 1
            logger.debug(
                "ws.redis_bridge.delivered action=%s key=%s from_worker=%s to_worker=%d",
                action, key, source_worker, _WORKER_ID,
            )
        except (json.JSONDecodeError, KeyError, TypeError) as exc:
            logger.warning("ws.redis_bridge.parse_error worker=%d %s", _WORKER_ID, exc)

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_stats(self) -> Dict[str, Any]:
        return {
            "running": self._running,
            "redis_connected": self._redis is not None,
            "channel_prefix": self._channel_prefix,
            "worker_id": _WORKER_ID,
            "reconnect_attempts": self._reconnect_attempts,
            "messages_published": self._messages_published,
            "messages_relayed": self._messages_relayed,
        }