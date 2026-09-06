"""
WebSocket↔EventBus Bridge
-------------------------
Declarative mapping from EventBus events to WebSocket push.

Instead of writing a ``Listener`` subclass for every event→device
mapping, register a one-liner::

    ws_bridge.bridge(
        event="order.print_job",
        target=lambda e: e.payload.get("device_id"),
    )

    ws_bridge.bridge(
        event="kiosk.config_updated",
        target="kiosk-42",
    )

The bridge creates the underlying ``Listener`` automatically and
tracks listener stats in the ``StatsCollector``.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Callable, Dict, Optional, Union

from swx_core.events.dispatcher import Event
from swx_core.websocket.manager import ConnectionManager
from swx_core.realtime.stats import StatsCollector

logger = logging.getLogger(__name__)

TargetResolver = Union[str, Callable[[Event], str]]


class WSBridge:
    """Maps EventBus events to WebSocket push with zero boilerplate.

    Each call to ``bridge()`` registers an EventBus listener that
    formats the event and sends it through the ``ConnectionManager``.
    If the target connection is not active, the message is queued for
    drain-on-reconnect.
    """

    def __init__(
        self,
        ws_manager: ConnectionManager,
        event_bus: Any = None,
        stats: Optional[StatsCollector] = None,
    ) -> None:
        self._ws = ws_manager
        self._bus = event_bus or _import_event_bus()
        self._stats = stats
        self._registrations: Dict[str, tuple[str, Any]] = {}

    def bridge(
        self,
        event: str,
        target: TargetResolver,
        *,
        priority: int = 50,
    ) -> None:
        """Register an EventBus→WebSocket bridge.

        Args:
            event: EventBus event name (supports wildcards).
            target: Either a static connection key string, or a callable
                that receives the ``Event`` and returns a key string.
            priority: Listener priority (default 50).

        Returns:
            ``self``, for chaining.
        """
        listener_name = f"WSBridge[{event}]"

        if listener_name in self._registrations:
            self.unbridge(event)

        async def _handler(ev: Event) -> None:
            if self._stats:
                await self._stats.listener_received(listener_name)

            try:
                key = target(ev) if callable(target) else target
                if not key:
                    return

                message = json.dumps({"event": ev.name, "payload": ev.payload}, default=str)
                await self._ws.send(key, message)

                if self._stats:
                    await self._stats.listener_forwarded(listener_name)
            except Exception:
                logger.exception("ws.bridge_failed event=%s", ev.name)
                if self._stats:
                    await self._stats.listener_error(listener_name)

        self._bus.listen(event, _handler, priority=priority)
        self._registrations[listener_name] = (event, _handler)
        logger.info("ws.bridge_registered event=%s → target=%s", event, target if isinstance(target, str) else "<dynamic>")

    def unbridge(self, event: str) -> bool:
        """Remove a previously registered bridge for *event*."""
        listener_name = f"WSBridge[{event}]"
        entry = self._registrations.pop(listener_name, None)
        if entry is None:
            return False

        registered_event, handler = entry
        self._bus.forget(registered_event, handler)
        logger.info("ws.bridge_removed event=%s", event)
        return True


def _import_event_bus() -> Any:
    from swx_core.events.dispatcher import event_bus
    return event_bus