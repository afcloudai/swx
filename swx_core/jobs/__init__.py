"""Celery application factory for the ``[jobs]`` extra.

Ships the worker entry point the ``jobs`` extra promises. Usage::

    # swx_app/celery_app.py (project side)
    from swx_core.jobs import create_celery_app

    celery_app = create_celery_app()

Then run: ``celery -A swx_app.celery_app worker -l info``.

Without ``celery`` installed, every entry point raises ImportError with
install instructions — swx_core itself never imports this module at
boot time.
"""

try:
    from celery import Celery
except ImportError as _exc:
    raise ImportError(
        "swx_core.jobs requires the [jobs] extra: pip install swx-core[jobs]"
    ) from _exc

from typing import Optional

from celery import Celery

from swx_core.config.settings import settings

celery_app: Optional[Celery] = None


def create_celery_app(**overrides) -> Celery:
    """Build the SwX Celery app from settings.

    Args:
        **overrides: Forwarded to ``Celery(...)`` for app-specific needs.

    Returns:
        A configured Celery application.
    """
    broker = getattr(settings, "CELERY_BROKER_URL", None) or getattr(
        settings, "REDIS_URL", None
    ) or f"redis://{settings.REDIS_HOST}:{settings.REDIS_PORT}/{settings.REDIS_DB}"
    backend = getattr(settings, "CELERY_RESULT_BACKEND", None) or broker

    app = Celery(
        getattr(settings, "PROJECT_NAME", "swx"),
        broker=broker,
        backend=backend,
        **overrides,
    )

    app.conf.update(
        task_serializer="json",
        result_serializer="json",
        accept_content=["json"],
        timezone="UTC",
        enable_utc=True,
        task_track_started=True,
        broker_connection_retry_on_startup=True,
    )

    global celery_app
    celery_app = app
    return app


def get_celery_app() -> Celery:
    """Return the module-level Celery app, creating it on first call.

    Prefer an app-level Celery instance (registered on ``app.state`` or
    passed explicitly to ``check_celery``) when the host application
    configures its own.
    """
    if celery_app is None:
        create_celery_app()
    return celery_app


__all__ = ["create_celery_app", "get_celery_app", "celery_app"]