"""
Main Application Entry Point
----------------------------
Legacy entry point — delegates to :func:`swx_core.app_factory.create_swx_app`,
the canonical single boot path (providers, lifecycle services, middleware
stack, exception handlers, routes).

Run with::

    uvicorn swx_core.main:app --reload
"""

from swx_core.app_factory import create_swx_app
from swx_core.config.settings import settings

app = create_swx_app(
    title=settings.PROJECT_NAME,
    register_routes=True,
    register_middleware=True,
    install_exception_handlers=True,
    root_endpoint=True,
)