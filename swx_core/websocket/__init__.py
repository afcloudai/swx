"""
SwX WebSocket Package
---------------------
Framework primitives for reliable WebSocket connections:

* ``ConnectionManager`` — single-connection-per-key enforcement,
  pending message queue with drain-on-reconnect, and metrics.
* ``WSBridge`` — declarative EventBus→WebSocket push mapping.
"""

from swx_core.websocket.manager import ConnectionManager
from swx_core.websocket.bridge import WSBridge

__all__ = ["ConnectionManager", "WSBridge"]