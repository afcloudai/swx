# pyright: reportMissingTypeArgument=false, reportMissingImports=false

"""
OIDC provider routers
---------------------
HTTP surface of the OIDC identity provider module (SWX-IDM-001).

P1 (D-2): ``admin_router`` — first-party client CRUD under ``/admin/oidc``,
gated by ``AdminUserDep`` (domain) AND the strict ``idp:clients:<action>``
permission resolved over ``swx_admin_user_roles`` bindings (root operator per
``FIRST_SUPERUSER`` is carved out by ``has_admin_permission``). Grant
bindings with ``swx idp bind-admin``.

P2+ adds ``issuer_router`` (``/oidc/*``, discovery, JWKS) to this module.
"""

from uuid import UUID
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.ext.asyncio import AsyncSession

from swx_core.auth.admin.dependencies import AdminUserDep
from swx_core.auth.oidc_provider import admin as oidc_admin
from swx_core.auth.oidc_provider.models import OIDCClientCreate, OIDCClientPublic, OIDCClientUpdate
from swx_core.database.db import get_session
from swx_core.models.admin_user import AdminUser
from swx_core.config.settings import settings
from swx_core.rbac.helpers import has_admin_permission
from swx_core.services.channels.models import AlertActorType, AlertSeverity, AlertSource
from swx_core.services.alert_engine import alert_engine

from fastapi.responses import JSONResponse

from swx_core.auth.oidc_provider import keys as oidc_keys
from swx_core.auth.oidc_provider import grant_service
from swx_core.auth.oidc_provider import tokens as oidc_tokens
from swx_core.auth.oidc_provider.security import OIDCAuthzError

admin_router = APIRouter(prefix="/admin/oidc", tags=["Admin - OIDC"])

issuer_router = APIRouter()

_OPENID_SCOPES = ["openid", "profile", "phone"]
_OPENID_GRANT_TYPES = ["authorization_code", "refresh_token", "client_credentials"]
_OPENID_CLAIMS = [
    "iss", "sub", "aud", "exp", "iat", "auth_time", "nonce", "azp",
    "name", "phone", "phone_verified",
]


def _oidc_error_response(exc: OIDCAuthzError, www_authenticate: str | None = None) -> JSONResponse:
    headers = {"WWW-Authenticate": www_authenticate} if www_authenticate else None
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": exc.error, "error_description": exc.description},
        headers=headers,
    )


@issuer_router.get("/.well-known/openid-configuration", include_in_schema=False)
async def openid_configuration(request: Request) -> dict:
    """OIDC Discovery 1.0 §3 metadata; endpoints self-adapt to the mounted prefix."""
    issuer = grant_service.derive_issuer(request)
    endpoints = grant_service.issuer_endpoint_urls(issuer)
    return {
        "issuer": issuer,
        "authorization_endpoint": endpoints["authorization"],
        "token_endpoint": endpoints["token"],
        "userinfo_endpoint": endpoints["userinfo"],
        "revocation_endpoint": endpoints["revocation"],
        "jwks_uri": endpoints["jwks"],
        "response_types_supported": ["code"],
        "grant_types_supported": _OPENID_GRANT_TYPES,
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": sorted(oidc_keys.SUPPORTED_KEY_ALGORITHMS),
        "scopes_supported": _OPENID_SCOPES,
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
        "code_challenge_methods_supported": ["S256"],
        "claims_supported": _OPENID_CLAIMS,
        "claims_parameter_supported": False,
        "request_parameter_supported": False,
        "request_uri_parameter_supported": False,
    }


@issuer_router.get("/jwks.json", include_in_schema=False)
async def jwks(session: AsyncSession = Depends(get_session)) -> dict:
    """RFC 7517 JWKS — public halves of publishable signing keys."""
    return await oidc_keys.build_jwks(session)


@issuer_router.get("/oidc/authorize", include_in_schema=False)
async def authorize_endpoint(request: Request, session: AsyncSession = Depends(get_session)):
    params = {key: str(value) for key, value in request.query_params.items()}
    try:
        return await grant_service.authorize(session, request, params)
    except OIDCAuthzError as exc:
        return _oidc_error_response(exc)


@issuer_router.post("/oidc/token", include_in_schema=False)
async def token_endpoint(request: Request, session: AsyncSession = Depends(get_session)):
    form = {key: str(value) for key, value in (await request.form()).items()}
    try:
        return await grant_service.token(session, request, form)
    except OIDCAuthzError as exc:
        www_authenticate = 'Basic realm="swx-oidc"' if exc.status_code == 401 else None
        return _oidc_error_response(exc, www_authenticate)
    except oidc_tokens.OIDCSigningUnavailable as exc:
        return JSONResponse(
            status_code=503,
            content={"error": "temporarily_unavailable", "error_description": str(exc)},
        )


@issuer_router.post("/oidc/revoke", include_in_schema=False)
async def revoke_endpoint(request: Request, session: AsyncSession = Depends(get_session)):
    form = {key: str(value) for key, value in (await request.form()).items()}
    try:
        return await grant_service.revoke(session, request, form)
    except OIDCAuthzError as exc:
        www_authenticate = 'Basic realm="swx-oidc"' if exc.status_code == 401 else None
        return _oidc_error_response(exc, www_authenticate)


@issuer_router.get("/oidc/userinfo", include_in_schema=False)
async def userinfo_endpoint(request: Request, session: AsyncSession = Depends(get_session)):
    try:
        return await grant_service.userinfo(session, request)
    except OIDCAuthzError as exc:
        return _oidc_error_response(exc, f'Bearer error="{exc.error}"')

_CLIENT_PERMISSION_ACTIONS = {
    "read": "idp:clients:read",
    "write": "idp:clients:write",
    "manage": "idp:clients:manage",
}


def require_oidc_clients_permission(action: str):
    """Gate admin client routes on ``idp:clients:<action>`` (SPWX-IDM-001 D-2).

    Composes the admin-domain identity check (``AdminUserDep``) with the
    strict, no-bypass permission resolution over ``swx_admin_user_roles``;
    denies with 403 (and a PERMISSION_DENIED alert) when it is absent.
    """
    permission_name = _CLIENT_PERMISSION_ACTIONS[action]

    async def checker(
        admin_user: AdminUserDep,
        session: AsyncSession = Depends(get_session),
    ) -> AdminUser:
        if not await has_admin_permission(session, admin_user, permission_name, domain="admin"):
            await alert_engine.emit(
                severity=AlertSeverity.WARNING,
                source=AlertSource.RBAC,
                event_type="PERMISSION_DENIED",
                message=f"Admin {admin_user.email} denied permission: {permission_name}",
                actor_type=AlertActorType.ADMIN,
                actor_id=str(admin_user.id),
                resource_type="permission",
                resource_id=permission_name,
                metadata={"path": "/admin/oidc/clients"},
            )
            raise HTTPException(status_code=403, detail=f"Permission required: {permission_name}")
        return admin_user

    return checker


OidcClientsReadDep = Annotated[AdminUser, Depends(require_oidc_clients_permission("read"))]
OidcClientsWriteDep = Annotated[AdminUser, Depends(require_oidc_clients_permission("write"))]
OidcClientsManageDep = Annotated[AdminUser, Depends(require_oidc_clients_permission("manage"))]


def _to_http_error(exc: Exception) -> HTTPException:
    if isinstance(exc, oidc_admin.OIDCValidationError):
        return HTTPException(status_code=400, detail=str(exc))
    if isinstance(exc, ValueError):
        return HTTPException(status_code=404, detail=str(exc))
    return HTTPException(status_code=400, detail=str(exc))


@admin_router.get("/clients", response_model=list[OIDCClientPublic])
async def list_clients(
    _admin: OidcClientsReadDep,
    session: AsyncSession = Depends(get_session),
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=100, ge=1, le=200),
):
    return await oidc_admin.list_clients(session, skip=skip, limit=limit)


@admin_router.post("/clients", response_model=OIDCClientPublic, status_code=201)
async def create_client(
    _admin: OidcClientsWriteDep,
    body: OIDCClientCreate,
    request: Request,
    session: AsyncSession = Depends(get_session),
):
    try:
        return await oidc_admin.create_client(session, body, actor_id=str(_admin.id), request=request)
    except Exception as exc:  # noqa: BLE001
        raise _to_http_error(exc) from exc


@admin_router.get("/clients/{client_row_id}", response_model=OIDCClientPublic)
async def get_client(
    _admin: OidcClientsReadDep,
    client_row_id: UUID,
    session: AsyncSession = Depends(get_session),
):
    try:
        return await oidc_admin.get_client(session, client_row_id)
    except Exception as exc:
        raise _to_http_error(exc) from exc


@admin_router.put("/clients/{client_row_id}", response_model=OIDCClientPublic)
async def update_client(
    _admin: OidcClientsWriteDep,
    client_row_id: UUID,
    body: OIDCClientUpdate,
    request: Request,
    session: AsyncSession = Depends(get_session),
):
    try:
        return await oidc_admin.update_client(session, client_row_id, body, actor_id=str(_admin.id), request=request)
    except Exception as exc:
        raise _to_http_error(exc) from exc


@admin_router.delete("/clients/{client_row_id}", response_model=dict[str, int])
async def delete_client(
    _admin: OidcClientsManageDep,
    client_row_id: UUID,
    request: Request,
    session: AsyncSession = Depends(get_session),
):
    try:
        return await oidc_admin.delete_client(session, client_row_id, actor_id=str(_admin.id), request=request)
    except Exception as exc:
        raise _to_http_error(exc) from exc