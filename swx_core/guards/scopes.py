"""API-key scope enforcement dependencies.

FastAPI dependencies that enforce the scopes carried by an API-key
principal (``AuthenticatedUser.permissions`` contains ``resource:action``
strings loaded from ``swx_api_key_scope`` by ``APIKeyGuard.authenticate``).

Scope semantics match ``swx_core.services.auth.api_key_scope_service``:
``resource`` and ``action`` may each be ``*`` (wildcard) on the *granted*
side. Stored scopes are expanded by the guard, so checking here is a
wildcard-aware set-membership test.

Usage::

    from swx_core.guards.scopes import require_scope

    @router.get("/billing/invoices", dependencies=[Depends(require_scope("billing:read"))])
    async def list_invoices():
        ...

Works for both authentication surfaces:
- API-key principals: permissions are the key's stored scopes.
- JWT principals: permissions come from the token's ``permissions`` claim
  (empty for most users — pair with RBAC roles there). Superusers bypass.
"""

from typing import Optional

from fastapi import Depends, HTTPException, Request, status

from swx_core.guards.base import AuthenticatedUser
from swx_core.guards.guard_manager import GuardManager, get_guard_manager
from swx_core.utils.language_helper import translate

_WILDCARD = "*"


def _scope_matches(required_resource: str, required_action: str, granted: str) -> bool:
    """Check whether a granted ``resource:action`` scope satisfies a requirement.

    Malformed/foreign permission strings (e.g. ``"admin"`` from JWT claims)
    never match — they carry no ``:`` separator.
    """
    granted_resource, separator, granted_action = granted.partition(":")
    if not separator:
        return False
    return (
        granted_resource in (required_resource, _WILDCARD)
        and granted_action in (required_action, _WILDCARD)
    )


def _has_scope(user: AuthenticatedUser, resource: str, action: str) -> bool:
    """Fail-closed scope check on a principal (superusers bypass)."""
    if user.is_superuser:
        return True
    return any(_scope_matches(resource, action, granted) for granted in user.permissions)


def _require_authenticated(
    user: Optional[AuthenticatedUser],
    request: Request,
    optional: bool,
) -> Optional[AuthenticatedUser]:
    """Resolve an unauthenticated principal against the optional flag."""
    if user is not None:
        return user
    if optional:
        return None
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=translate(request, "could_not_validate_credentials") or "Authentication required",
    )


def _parse_scope(scope: str) -> tuple[str, str]:
    if ":" not in scope:
        raise ValueError(f"Invalid scope {scope!r}: expected 'resource:action'")
    resource, action = scope.split(":", 1)
    return resource, action


def require_scope(scope: str, optional: bool = False):
    """Require an exact ``resource:action`` scope on the current principal.

    Args:
        scope: Required scope in ``resource:action`` form (e.g.
            ``"billing:read"``). Wildcards belong to the *granted* side
            (stored scopes), not the requirement.
        optional: When ``True``, unauthenticated requests resolve to ``None``
            instead of raising 401; scope enforcement still applies to any
            authenticated principal.

    Returns:
        A FastAPI dependency resolving to the authenticated principal (or
        ``None`` when ``optional=True`` and unauthenticated).

    Raises:
        HTTPException 401: Missing credentials (only when ``optional=False``).
        HTTPException 403: Principal authenticated but lacks the scope.
    """
    resource, action = _parse_scope(scope)

    async def scope_checker(
        request: Request,
        guard_manager: GuardManager = Depends(get_guard_manager),
    ) -> Optional[AuthenticatedUser]:
        user = await guard_manager.authenticate(request)
        principal = _require_authenticated(user, request, optional)
        if principal is None:
            return None
        if not _has_scope(principal, resource, action):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=translate(request, "user_lacks_required_permission")
                or f"Scope required: {scope}",
            )
        return principal

    return scope_checker


def require_any_scope(
    *scopes: str,
    all_required: bool = False,
    optional: bool = False,
):
    """Require any (default) or all of the given scopes.

    Args:
        *scopes: Scope requirements in ``resource:action`` form.
        all_required: ``True`` = every listed scope must be granted;
            ``False`` (default) = at least one suffices.
        optional: Same semantics as :func:`require_scope`.

    Returns:
        A FastAPI dependency resolving to the authenticated principal.
    """
    if not scopes:
        raise ValueError("require_any_scope() needs at least one scope")
    parsed = [_parse_scope(scope) for scope in scopes]

    async def scope_checker(
        request: Request,
        guard_manager: GuardManager = Depends(get_guard_manager),
    ) -> Optional[AuthenticatedUser]:
        user = await guard_manager.authenticate(request)
        principal = _require_authenticated(user, request, optional)
        if principal is None:
            return None

        predicate = all if all_required else any
        if not predicate(
            _has_scope(principal, resource, action) for resource, action in parsed
        ):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=translate(request, "user_lacks_required_permission")
                or f"Scope(s) required: {', '.join(scopes)}",
            )
        return principal

    return scope_checker


__all__ = ["require_any_scope", "require_scope"]