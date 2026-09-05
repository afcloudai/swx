"""
SwX SSE Package
---------------
Server-Sent Events infrastructure:

* ``SSEManager`` — subscribe, broadcast, keepalive, cleanup
* ``SSEEventStore`` — Redis sorted-set persistence for Last-Event-ID replay
* ``SSEBridge`` — declarative EventBus→SSE channel mapping
* ``EventSerializerRegistry`` — declarative event→SSE-type mapping
* ``sse_serializers`` — module-level singleton registry
"""

from swx_core.sse.manager import SSEManager
from swx_core.sse.event_store import SSEEventStore
from swx_core.sse.bridge import SSEBridge
from swx_core.sse.serializer import EventSerializerRegistry, sse_serializers

__all__ = [
    "SSEManager",
    "SSEEventStore",
    "SSEBridge",
    "EventSerializerRegistry",
    "sse_serializers",
]