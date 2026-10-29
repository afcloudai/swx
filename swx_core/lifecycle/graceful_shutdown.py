"""
Graceful Shutdown
-----------------
Handles SIGTERM by stopping new connections and draining existing SSE/WS
connections before exit.  Integrates with the LifecycleManager stop order.

Usage (in ``create_swx_app()``)::

    from swx_core.lifecycle import GracefulShutdown

    gs = GracefulShutdown(drain_timeout_seconds=30)
    gs.install(app)

On SIGTERM:
1.  Stop accepting new HTTP/TLS connections (platform-dependent).
2.  Set a deadline (default 30 s).
3.  Wait for SSE and WebSocket connections to drain.
4.  Force-close remaining connections after the deadline.
5.  Log shutdown progress per connection type.
"""

from __future__ import annotations

import asyncio
import os
import signal
import logging
from typing import Any, Optional

from swx_core.middleware.logging_middleware import logger

_SHUTDOWN_SIGNALS = [signal.SIGINT]
if hasattr(signal, "SIGTERM"):
    _SHUTDOWN_SIGNALS.append(signal.SIGTERM)


class GracefulShutdown:
    """Install a SIGTERM handler that drains SSE/WS connections before exit.

    Args:
        drain_timeout_seconds: Maximum seconds to wait for connections
            to drain before forcing shutdown.
    """

    def __init__(self, drain_timeout_seconds: int = 30) -> None:
        self._drain_timeout = drain_timeout_seconds
        self._shutting_down = False
        self._drain_event = asyncio.Event()
        self._app: Any = None

    @property
    def is_shutting_down(self) -> bool:
        return self._shutting_down

    def install(self, app: Any) -> None:
        """Register signal handlers on the running event loop.

        Should be called from within an async context (e.g. during
        lifespan startup) so that ``loop.add_signal_handler`` works.
        """
        self._app = app
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            logger.warning("graceful_shutdown.no_event_loop")
            return

        for sig in _SHUTDOWN_SIGNALS:
            loop.add_signal_handler(sig, self._handle_signal, sig)

        logger.info("graceful_shutdown.installed drain_timeout=%ds", self._drain_timeout)

    def _handle_signal(self, sig: signal.Signals) -> None:
        sig_name = sig.name
        logger.info("graceful_shutdown.signal_received signal=%s", sig_name)

        if self._shutting_down:
            logger.warning("graceful_shutdown.already_shutting_down signal=%s", sig_name)
            return

        self._shutting_down = True

        try:
            loop = asyncio.get_running_loop()
            loop.create_task(self._drain_and_exit(sig_name))
        except RuntimeError:
            logger.critical("graceful_shutdown.no_event_loop_on_signal")

    async def _drain_and_exit(self, sig_name: str) -> None:
        logger.info("graceful_shutdown.draining timeout=%ds", self._drain_timeout)

        try:
            await asyncio.wait_for(self._drain_event.wait(), timeout=self._drain_timeout)
            logger.info("graceful_shutdown.drained")
        except asyncio.TimeoutError:
            logger.warning("graceful_shutdown.drain_timeout_exceeded")

        logger.info("graceful_shutdown.exiting signal=%s", sig_name)
        os._exit(0)

    def notify_drained(self) -> None:
        """Called by SSE/WS managers when all connections are closed."""
        self._drain_event.set()

    async def drain_check(self) -> bool:
        """Return True if all real-time connections have drained or shutdown is in progress."""
        return self._drain_event.is_set()