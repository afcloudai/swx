"""API Key Authentication Guard (SOC 2 CC6.1).

Authenticates requests via the ``X-API-Key`` header (default) and enforces
the per-key scopes stored in ``swx_api_key_scope``.

Security model:
- Keys are accepted from the header only. A legacy ``?api_key=`` query
  parameter is opt-in via ``query_param`` (or the ``API_KEY_QUERY_PARAM``
  setting) because URL-carried credentials leak into access logs, proxy
  logs, browser history and referrer headers.
- On success the guard loads the key's active scopes and maps them onto
  ``AuthenticatedUser.permissions`` as ``resource:action`` strings, so
  ``require_permissions("billing:read")`` and :func:`require_scope` both
  enforce scopes for API-key principals. A key with no scopes can only
  reach endpoints that do not require a permission/scope.

Delegates all DB operations to the api_key_service layer, following
the SWX Controller → Service → Repository pattern.
"""

from typing import Any, Dict, Optional

from fastapi import Request
from sqlalchemy.ext.asyncio import AsyncSession

from swx_core.guards.base import AuthenticatedUser, BaseGuard
from swx_core.middleware.logging_middleware import logger


class APIKeyGuard(BaseGuard):
    """API Key authentication guard.

    Delegates validation, scope loading and revocation to api_key_service,
    following the SWX pattern (guard → service → repository).
    """

    def __init__(
        self,
        header_name: str = "X-API-Key",
        query_param: Optional[str] = None,
    ):
        """Create the guard.

        Args:
            header_name: Header carrying the raw key (default ``X-API-Key``).
            query_param: Optional name of a query parameter that may also
                carry the key. ``None`` (default) = header-only. Enabling
                query auth weakens security — keys end up in server access
                logs, proxies, browser history and referrer headers.
        """
        self.header_name = header_name
        self.query_param = query_param

    @property
    def name(self) -> str:
        return "api_key"

    async def authenticate(self, request: Request) -> Optional[AuthenticatedUser]:
        """Authenticate via API key and map stored scopes onto permissions."""
        raw_key = self._extract_key(request)
        if not raw_key:
            return None

        session = self._get_session(request)
        if session is None:
            logger.warning("No DB session available for API key authentication")
            return None

        from swx_core.services.auth import api_key_service

        key_public = await api_key_service.validate_api_key(session, raw_key)
        if key_public is None:
            logger.warning(
                "Invalid or expired API key from %s",
                request.client.host if request.client else "unknown",
            )
            return None

        scope_strings = await api_key_service.get_key_scope_strings(session, key_public.id)

        return AuthenticatedUser(
            id=str(key_public.user_id),
            email="",
            type="api_key",
            roles=["api_user"],
            permissions=scope_strings,
            is_superuser=False,
            is_active=True,
            metadata={
                "key_id": str(key_public.id),
                "key_prefix": key_public.key_prefix,
                "key_name": key_public.name,
                "key_environment": key_public.environment,
                "scopes": scope_strings,
            },
        )

    async def validate_token(
        self, token: str, session: Optional[AsyncSession] = None
    ) -> Dict[str, Any]:
        """Validate API key by delegating to the service layer.

        Args:
            token: The raw API key.
            session: Optional request-scoped session (preferred). When
                ``None`` a standalone session is opened — use for
                out-of-band validation outside the request DI cycle.
        """
        if session is None:
            from swx_core.database.db import AsyncSessionLocal
            async with AsyncSessionLocal() as standalone_session:
                return await self._validate_key(standalone_session, token)
        return await self._validate_key(session, token)

    async def _validate_key(self, session: AsyncSession, token: str) -> Dict[str, Any]:
        from swx_core.services.auth import api_key_service

        key_public = await api_key_service.validate_api_key(session, token)
        if key_public is None:
            return {"valid": False, "key_prefix": token[:8] if token else ""}
        return {
            "valid": True,
            "key_prefix": key_public.key_prefix,
            "key_id": str(key_public.id),
        }

    async def create_token(self, user: Any, audience: Optional[str] = None, **claims) -> str:
        """API keys are not created as tokens — use the API key management endpoints instead."""
        raise NotImplementedError("APIKeyGuard does not create tokens. Use the API key management endpoints.")

    async def revoke_token(
        self, token: str, session: Optional[AsyncSession] = None
    ) -> bool:
        """Revoke an API key via the service layer (audited, event-emitting).

        Args:
            token: The raw API key.
            session: Optional request-scoped session (preferred). When
                ``None`` a standalone session is opened — use outside the
                request DI cycle.
        """
        if session is None:
            from swx_core.database.db import AsyncSessionLocal
            async with AsyncSessionLocal() as standalone_session:
                return await self._revoke_key(standalone_session, token)
        return await self._revoke_key(session, token)

    async def _revoke_key(self, session: AsyncSession, token: str) -> bool:
        from fastapi import HTTPException

        from swx_core.services.auth import api_key_service

        key_public = await api_key_service.validate_api_key(session, token)
        if key_public is None:
            return False

        try:
            await api_key_service.revoke_api_key(session, key_public.id, key_public.user_id)
            return True
        except HTTPException:
            # Key vanished between validation and revocation (or was already deactivated).
            return False

    def _extract_key(self, request: Request) -> Optional[str]:
        """Extract API key from the request header (and query param if enabled)."""
        key = request.headers.get(self.header_name)
        if key:
            return key

        if self.query_param is not None:
            key = request.query_params.get(self.query_param)
            if key:
                return key

        return None

    def _get_session(self, request: Request) -> Optional[AsyncSession]:
        """Resolve the DB session for this request.

        Order:
        1. ``request.state.db_session`` (set by app-level middleware).
        2. ``request.app.state.db_session`` (set by simple bootstrap).
        3. Container-scoped ``db.session`` (SwX DI, bound per request by
           ``ContainerMiddleware`` when the database provider is booted).
        """
        session = getattr(request.state, "db_session", None) or getattr(
            request.app.state, "db_session", None
        )
        if session is not None:
            return session

        container = getattr(request.app.state, "container", None)
        if container is not None and container.bound("db.session"):
            return container.make("db.session")

        return None

    def can_revoke(self) -> bool:
        """Check if revocation is supported."""
        return True