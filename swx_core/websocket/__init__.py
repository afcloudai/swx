"""
SwX WebSocket Package
---------------------
Framework primitives for reliable WebSocket connections:

* ``ConnectionManager`` — single-connection-per-key enforcement,
  pending message queue with drain-on-reconnect, metrics, and
  optional Redis relay for cross-worker delivery.
* ``WSBridge`` — declarative EventBus→WebSocket push mapping.
* ``WSRedisBridge`` — Redis Pub/Sub bridge for cross-worker
  WebSocket message delivery.
"""

from swx_core.websocket.manager import ConnectionManager
from swx_core.websocket.bridge import WSBridge
from swx_core.websocket.redis_bridge import WSRedisBridge

__all__ = ["ConnectionManager", "WSBridge", "WSRedisBridge"]