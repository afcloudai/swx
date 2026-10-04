"""
Session Middleware
------------------
Configures session management using Starlette's SessionMiddleware.

Settings come from SecuritySettingsMixin:
- SESSION_MAX_AGE (default 86400)
- SESSION_SAME_SITE (default "lax")
- HTTPS_ONLY (default derived from ENVIRONMENT: True in production/staging)
"""

from starlette.middleware.sessions import SessionMiddleware
from swx_core.config.settings import settings


def setup_session_middleware(app):
    """
    Configures SessionMiddleware from settings.

    Args:
        app: The FastAPI application instance.
    """
    https_only = settings.HTTPS_ONLY
    if https_only is None:
        https_only = settings.ENVIRONMENT in ("production", "staging")

    app.add_middleware(
        SessionMiddleware,
        secret_key=settings.SECRET_KEY,
        max_age=settings.SESSION_MAX_AGE,
        same_site=settings.SESSION_SAME_SITE,
        https_only=https_only,
    )