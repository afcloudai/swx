"""
WebSocket Status Routes
-----------------------
Admin observability endpoint for WebSocket connection state.

Returns per-connection metadata (worker, connected_at, pending count)
and aggregate metrics (opened, closed, sent, queued, failed) along
with Redis bridge status when available.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from fastapi import APIRouter

router = APIRouter(prefix="/admin/ws", tags=["Admin - WebSocket"])


@router.get("/status")
async def ws_status() -> Dict[str, Any]:
    """Return full WebSocket manager status for this worker.

    Includes connection metadata, aggregate metrics, and Redis bridge stats.
    """
    from swx_core.websocket.manager import ConnectionManager

    mgr: Optional[ConnectionManager] = ConnectionManager.get_instance()
    if mgr is None:
        return {"status": "not_initialised", "worker_id": None}

    result: Dict[str, Any] = {
        "status": mgr.status,
        "worker_id": mgr.worker_id,
        "active_connections": mgr.connection_count,
        "connections": mgr.all_connection_info(),
        "metrics": mgr.metrics,
        "redis_bridge": None,
    }

    bridge_stats = mgr.bridge_stats
    if bridge_stats is not None:
        result["redis_bridge"] = bridge_stats

    return result