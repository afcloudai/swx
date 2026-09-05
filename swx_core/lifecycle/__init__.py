"""
SwX Lifecycle Module
--------------------
Deterministic startup/shutdown for long-running services.

Re-exports ``LifecycleManager``, ``LifecycleService``, and ``LifecycleError``
from the core module, plus ``GracefulShutdown`` for SIGTERM handling.
"""

from swx_core.lifecycle.core import LifecycleManager, LifecycleError, LifecycleService
from swx_core.lifecycle.graceful_shutdown import GracefulShutdown

__all__ = ["LifecycleManager", "LifecycleError", "LifecycleService", "GracefulShutdown"]