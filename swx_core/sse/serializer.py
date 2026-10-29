"""
SSE Event Serializer Registry
-------------------------------
Declarative mapping from EventBus event names to SSE wire formats.

Instead of hard-coding ``event:`` field values and payload shapes inside
route handlers, register a one-liner::

    from swx_core.sse.serializer import sse_serializers

    sse_serializers.register(
        event="order.paid",
        sse_type="order-update",
        payload_filter=lambda p: {"orderId": p["order_id"], "status": "paid"},
    )

When ``SSEBridge`` broadcasts an event it will look up a serializer for
``event.name``.  If one exists, the serializer controls the ``event:``
field and payload projection; otherwise the default pass-through applies
(the raw EventBus event name and full payload).

The registry is a module-level singleton (``sse_serializers``) so it can
be imported from any module without passing references around.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Optional

logger = logging.getLogger(__name__)


@dataclass
class SerializerEntry:
    """A registered serializer for a specific EventBus event name."""

    sse_type: str
    payload_filter: Optional[Callable[[Dict[str, Any]], Dict[str, Any]]] = None


class EventSerializerRegistry:
    """Maps EventBus event names to SSE wire formats.

    Thread-safety: registration happens at import/setup time (single-threaded).
    Lookup happens at request time (concurrent reads are safe on the GIL).
    """

    def __init__(self) -> None:
        self._entries: Dict[str, SerializerEntry] = {}

    def register(
        self,
        event: str,
        sse_type: str,
        *,
        payload_filter: Optional[Callable[[Dict[str, Any]], Dict[str, Any]]] = None,
    ) -> "EventSerializerRegistry":
        """Register a serializer for an EventBus event name.

        Args:
            event: Exact EventBus event name (e.g. ``"order.paid"``).
            sse_type: Value for the SSE ``event:`` field
                (e.g. ``"order-update"``).  This lets the frontend
                subscribe to a stable event type even when the backend
                event name changes.
            payload_filter: Optional callable that receives the raw
                ``Event.payload`` dict and returns a *projected* dict
                for the wire.  Use this to strip internal fields or
                reshape the payload for the client.

        Returns:
            ``self``, for chaining.

        Raises:
            ValueError: If *event* is already registered.
        """
        if event in self._entries:
            raise ValueError(f"Serializer for event {event!r} is already registered")
        self._entries[event] = SerializerEntry(
            sse_type=sse_type,
            payload_filter=payload_filter,
        )
        logger.info("sse.serializer_registered event=%s → sse_type=%s", event, sse_type)
        return self

    def unregister(self, event: str) -> bool:
        """Remove a previously registered serializer.

        Returns ``True`` if the serializer existed and was removed.
        """
        entry = self._entries.pop(event, None)
        if entry is not None:
            logger.info("sse.serializer_unregistered event=%s", event)
            return True
        return False

    def lookup(self, event: str) -> Optional[SerializerEntry]:
        """Return the serializer for *event*, or ``None`` if unregistered."""
        return self._entries.get(event)

    def serialize(self, event_name: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Apply the registered serializer (if any) and return the SSE-ready dict.

        When a serializer is registered for *event_name*:
        * The ``event`` field is set to the serializer's ``sse_type``.
        * The ``payload`` is passed through the serializer's ``payload_filter``
          (or left unchanged if no filter was provided).

        When no serializer exists, the raw event name and payload pass
        through unchanged.
        """
        entry = self._entries.get(event_name)
        if entry is None:
            return {"event": event_name, "payload": payload}

        filtered = entry.payload_filter(payload) if entry.payload_filter else payload
        return {"event": entry.sse_type, "payload": filtered}

    def __contains__(self, event: str) -> bool:
        return event in self._entries

    def __len__(self) -> int:
        return len(self._entries)


# Module-level singleton for convenience.
sse_serializers = EventSerializerRegistry()