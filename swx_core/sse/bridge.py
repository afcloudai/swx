"""
SSE Bridge
----------
Declarative mapping from EventBus events to SSE channels.

Instead of writing a ``Listener`` subclass for every event→channel
mapping, register a one-liner::

    sse_bridge.bridge(
        event="order.paid",
        channel=lambda e: f"orders:{e.payload['order_id']}",
    )

    sse_bridge.bridge(
        event="device.heartbeat",
        channel="admin:devices",
    )

The bridge creates the underlying ``Listener`` automatically and tracks
listener stats in the ``StatsCollector``.
"""

from __future__ import annotations

import logging
from typing import Any, Callable, Dict, Optional, Union

from swx_core.events.dispatcher import Event
from swx_core.sse.manager import SSEManager
from swx_core.sse.serializer import EventSerializerRegistry, sse_serializers
from swx_core.realtime.stats import StatsCollector

logger = logging.getLogger(__name__)

ChannelResolver = Union[str, Callable[[Event], str]]


class SSEBridge:
    """Maps EventBus events to SSE channels with zero boilerplate.

    Each call to ``bridge()`` registers an EventBus listener that
    formats the event and broadcasts it through the ``SSEManager``.
    If an ``EventSerializerRegistry`` entry exists for the event,
    it controls the ``event:`` field and payload projection.
    """

    def __init__(
        self,
        sse_manager: SSEManager,
        event_bus: Any = None,
        stats: Optional[StatsCollector] = None,
        serializer_registry: Optional[EventSerializerRegistry] = None,
    ) -> None:
        self._sse = sse_manager
        self._bus = event_bus or globals().get("event_bus") or _import_event_bus()
        self._stats = stats
        self._serializers = serializer_registry or sse_serializers
        self._registrations: Dict[str, tuple[str, Any]] = {}

    def bridge(
        self,
        event: str,
        channel: ChannelResolver,
        *,
        priority: int = 50,
        event_type: Optional[str] = None,
    ) -> None:
        """Register an EventBus→SSE bridge.

        Args:
            event: EventBus event name (supports wildcards).
            channel: Either a static channel string or a callable that
                receives the ``Event`` and returns a channel string.
            priority: Listener priority (default 50).
            event_type: Optional SSE ``event:`` field value.  When
                ``None``, the EventBus event name is used.

        Returns:
            ``self``, for chaining.
        """
        listener_name = f"SSEBridge[{event}]"

        if listener_name in self._registrations:
            self.unbridge(event)

        async def _handler(ev: Event) -> None:
            if self._stats:
                await self._stats.listener_received(listener_name)

            try:
                ch = channel(ev) if callable(channel) else channel

                serialized = self._serializers.serialize(ev.name, ev.payload)
                if event_type is not None:
                    serialized["event"] = event_type
                payload: Dict[str, Any] = serialized

                await self._sse.broadcast(ch, payload)

                if self._stats:
                    await self._stats.listener_forwarded(listener_name)
            except Exception:
                logger.exception("sse.bridge_failed event=%s", ev.name)
                if self._stats:
                    await self._stats.listener_error(listener_name)

        self._bus.listen(event, _handler, priority=priority)
        self._registrations[listener_name] = (event, _handler)
        logger.info("sse.bridge_registered event=%s → channel=%s", event, channel if isinstance(channel, str) else "<dynamic>")

    def unbridge(self, event: str) -> bool:
        """Remove a previously registered bridge for *event*."""
        listener_name = f"SSEBridge[{event}]"
        entry = self._registrations.pop(listener_name, None)
        if entry is None:
            return False

        registered_event, handler = entry
        self._bus.forget(registered_event, handler)
        logger.info("sse.bridge_removed event=%s", event)
        return True


def _import_event_bus() -> Any:
    """Lazy import to avoid circular dependency at module level."""
    from swx_core.events.dispatcher import event_bus
    return event_bus