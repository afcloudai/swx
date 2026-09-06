"""
WebSocket Routes
----------------
Framework-level WebSocket endpoint for real-time connectivity.

Exposes ``websocket_router`` (not ``router``) so the auto-discovery system
in ``swx_core.router`` mounts it alongside HTTP routes from the same module.

Modules that wish to expose their own WebSocket routes should likewise define
a ``websocket_router`` attribute — an ``APIRouter`` with ``@router.websocket``
endpoints.
"""

from __future__ import annotations

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from swx_core.websocket.manager import ConnectionManager

ws_manager = ConnectionManager()

websocket_router = APIRouter()


@websocket_router.websocket("/ws/{device_id}")
async def ws_endpoint(websocket: WebSocket, device_id: str) -> None:
    """Primary WebSocket endpoint.

    Accepts the connection, registers it under *device_id*, and echoes
    inbound messages until the client disconnects.  On reconnect, any
    messages queued while offline are automatically drained.
    """
    await ws_manager.connect(device_id, websocket)
    try:
        while True:
            data = await websocket.receive_text()
            await ws_manager.handle_message(device_id, data)
    except WebSocketDisconnect:
        pass
    finally:
        await ws_manager.disconnect(device_id)