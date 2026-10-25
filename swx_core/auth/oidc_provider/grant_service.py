# pyright: reportMissingImports=false, reportAny=false, reportExplicitAny=false, reportUnknownMemberType=false, reportUnknownArgumentType=false, reportUnusedCallResult=false, reportAttributeAccessIssue=false, reportOptionalMemberAccess=false, reportOptionalSubscript=false

"""
OIDC grant service (SWX-IDM-001, D-3)
-------------------------------------
Business layer behind the issuer endpoints:

- ``authorize``/``complete_authorize`` — login-redirect flow over the platform
  session middleware; pending grants live in ``request.session``
- ``token`` — authorization_code (single-use, PKCE-verified, redirect-exact),
  refresh_token (rotation **with reuse detection → family revocation**),
  client_credentials (confidential first-party only)
- ``revoke`` — RFC 7009 (200 on success, silent on unknown tokens; never leaks validity)
- ``userinfo`` — Bearer-only, audience-bound, scope-gated claims (no email, ever)

Every refusal is audited (fail-closed, audited — ticket AC).
"""

import secrets
import uuid
from datetime import datetime, timedelta
from typing import Any
from urllib.parse import quote, urlencode

from fastapi import Request
from fastapi.responses import RedirectResponse

from swx_core.auth.core.bearer_or_cookie import BearerOrCookieAuth
from swx_core.auth.core.jwt import TokenAudience, decode_token
from swx_core.auth.oidc_provider import repositories as oidc_repo
from swx_core.auth.oidc_provider import security as oidc_security
from swx_core.auth.oidc_provider import tokens as oidc_tokens
from swx_core.auth.oidc_provider.models import REFRESH_STATUS_ACTIVE
from swx_core.auth.oidc_provider.security import OIDCAuthzError
from swx_core.config.settings import settings
from swx_core.models.user import User
from swx_core.services.audit_logger import ActorType, AuditAction, AuditLogger, AuditOutcome
from swx_core.utils.time import utc_now

_PENDING_GRANT_KEY = "oidc_pending_grant"

_ACR_PWD = "urn:swx:acr:pwd"
_ACR_MFA = "urn:swx:acr:mfa"
_DEFAULT_AMR = ["pwd"]


def derive_issuer(request: Request) -> str:
    configured = getattr(settings, "SWX_OIDC_ISSUER", None)
    if configured:
        return configured.rstrip("/")
    base = str(request.base_url).rstrip("/")
    prefix = settings.ROUTE_PREFIX.strip("/")
    return f"{base}/{prefix}" if prefix else base


def issuer_endpoint_urls(issuer: str) -> dict[str, str]:
    return {
        "authorization": f"{issuer}/oidc/authorize",
        "token": f"{issuer}/oidc/token",
        "userinfo": f"{issuer}/oidc/userinfo",
        "revocation": f"{issuer}/oidc/revoke",
        "introspection": f"{issuer}/oidc/introspect",
        "end_session": f"{issuer}/oidc/logout",
        "jwks": f"{issuer}/jwks.json",
    }


async def end_session(session: Any, request: Request, params: dict[str, Any]) -> Any:
    """RP-initiated logout (end_session_endpoint).

    Revokes the subject's platform refresh tokens/sessions and EVERY OIDC
    refresh family, clears the platform session, then redirects ONLY to an
    exactly-registered ``post_logout_redirect_uri`` (never attacker URLs).
    """
    import uuid as _uuid

    hint = params.get("id_token_hint")
    post_logout_redirect_uri = params.get("post_logout_redirect_uri")
    state = params.get("state") or None

    client: Any = None
    subject: _uuid.UUID | None = None
    if hint:
        try:
            payload = await oidc_tokens.verify_oidc_access_token(session, str(hint))
        except Exception:
            await _audit(session, AuditAction.AUTH_LOGOUT, outcome=AuditOutcome.FAILURE,
                         context={"path": "end_session", "reason": "invalid_id_token_hint"})
            raise OIDCAuthzError("invalid_request", "Invalid id_token_hint", status_code=400) from None
        audience = payload.get("aud")
        if isinstance(audience, str):
            client = await oidc_repo.get_client_by_public_id(session, audience)
        subject_value = payload.get("sub")
        try:
            subject = _uuid.UUID(str(subject_value))
        except ValueError:
            raise OIDCAuthzError("invalid_request", "Invalid id_token_hint", status_code=400) from None

    if post_logout_redirect_uri:
        if client is None:
            await _audit(session, AuditAction.AUTH_LOGOUT, outcome=AuditOutcome.FAILURE,
                         context={"path": "end_session", "reason": "post_logout_without_client"})
            raise OIDCAuthzError("invalid_request", "post_logout_redirect_uri requires a valid id_token_hint", status_code=400)
        if post_logout_redirect_uri not in (client.post_logout_redirect_uris or []):
            await _audit(session, AuditAction.AUTH_LOGOUT, outcome=AuditOutcome.FAILURE,
                         context={"path": "end_session", "reason": "unregistered_post_logout_redirect"})
            raise OIDCAuthzError("invalid_request", "post_logout_redirect_uri is not registered", status_code=400)

    if subject is not None:
        user = await session.get(User, subject)
        if user is not None:
            from swx_core.security.refresh_token_service import revoke_all_tokens

            await revoke_all_tokens(session, str(user.email))
        revoked = await oidc_repo.revoke_families_for_user(session, subject)
        await _audit(
            session,
            AuditAction.AUTH_TOKEN_REVOKED,
            context={"path": "end_session", "families_revoked": revoked},
            actor_id=str(subject),
            resource_id=str(subject),
            resource_type="oidc_session",
        )
        await _audit(session, AuditAction.AUTH_LOGOUT, context={"path": "end_session"}, actor_id=str(subject))

    request.session.pop(_PENDING_GRANT_KEY, None)
    request.session.pop("swx_amr", None)

    if post_logout_redirect_uri:
        response = RedirectResponse(post_logout_redirect_uri, status_code=303)
    else:
        from fastapi.responses import JSONResponse

        response = JSONResponse(status_code=200, content={"status": "logged_out"})
    for cookie in (settings.COOKIE_ACCESS_TOKEN_NAME, settings.COOKIE_REFRESH_TOKEN_NAME):
        response.delete_cookie(cookie)
    return response


async def introspect(session: Any, request: Request, form: dict[str, Any]) -> dict[str, Any]:
    """RFC 7662 — token introspection for confidential clients (no validity leak)."""
    client = await oidc_security.authenticate_client(session, request, form)
    if client.client_secret_hash is None:
        await _audit(session, AuditAction.AUTH_OIDC_TOKEN_DENIED, outcome=AuditOutcome.FAILURE,
                     context={"path": "introspect", "reason": "public_client"})
        raise OIDCAuthzError("invalid_client", "Introspection requires a confidential client", status_code=401)
    token_value = str(form.get("token") or "")
    if not token_value:
        raise OIDCAuthzError("invalid_request", "token is required")

    inactive: dict[str, Any] = {"active": False}
    if "." in token_value:
        payload: dict[str, Any] | None = None
        try:
            payload = await oidc_tokens.verify_oidc_access_token(session, token_value)
        except Exception:
            payload = None
        if payload is None:
            return inactive
        expected_audience = f"oidc_client:{client.client_id}"
        if payload.get("aud") != expected_audience:
            await _audit(session, AuditAction.AUTH_OIDC_TOKEN_DENIED, outcome=AuditOutcome.FAILURE,
                         context={"path": "introspect", "reason": "cross_client_token", "client_id": client.client_id},
                         actor_id=client.client_id)
            return inactive
        exp = payload.get("exp")
        now = utc_now().timestamp()
        if exp and float(exp) <= now:
            return inactive
        jti = payload.get("jti")
        blacklist = _get_token_blacklist()
        if blacklist is not None and jti and await blacklist.is_revoked_by_jti(jti):
            return inactive
        return {
            "active": True,
            "scope": payload.get("scope", ""),
            "client_id": client.client_id,
            "sub": str(payload.get("sub")),
            "exp": exp,
            "iat": payload.get("iat"),
            "jti": jti,
        }

    row = await oidc_repo.get_refresh_token_by_hash(session, oidc_tokens.sha256_hex(token_value))
    if row is None or row.client_id != client.client_id:
        return inactive
    if row.status != REFRESH_STATUS_ACTIVE or row.expires_at <= utc_now():
        return inactive
    return {
        "active": True,
        "scope": row.scope,
        "client_id": row.client_id,
        "sub": str(row.user_id),
    }


def _get_token_blacklist():
    """Resolve the token blacklist from the DI container, or None if unavailable."""
    try:
        from swx_core.container.container import get_container

        container = get_container()
        if container.bound("auth.token_blacklist"):
            return container.make("auth.token_blacklist")
    except Exception:
        return None
    return None


async def _audit(
    session: Any,
    action: str | AuditAction,
    *,
    outcome: AuditOutcome = AuditOutcome.SUCCESS,
    context: dict[str, Any] | None = None,
    actor_id: str | None = None,
    resource_type: str | None = None,
    resource_id: str | None = None,
) -> None:
    await AuditLogger(session).log_event(
        action=action,
        actor_type=ActorType.USER,
        actor_id=actor_id,
        resource_type=resource_type,
        resource_id=resource_id,
        outcome=outcome,
        context=context or {},
    )


async def _resolve_optional_user(session: Any, request: Request) -> tuple[User | None, dict[str, Any] | None]:
    """Best-effort current-user resolution for /authorize (never raises).

    Returns ``(user, decoded_platform_payload)``; ``payload["iat"]`` feeds
    ``auth_time`` into OIDC id_tokens.
    """
    from swx_core.auth.user.dependencies import get_current_user

    try:
        token = await BearerOrCookieAuth()(request)
        if token is None:
            return None, None
        payload = decode_token(token.credentials, TokenAudience.USER)
        user = await get_current_user(session, token, request)
    except Exception:
        return None, None
    if user is None:
        return None, None
    return user, payload


def _error_redirect(redirect_uri: str, error: str, description: str, state: str | None) -> RedirectResponse:
    params: dict[str, str] = {"error": error, "error_description": description}
    if state is not None:
        params["state"] = state
    return RedirectResponse(f"{redirect_uri}?{urlencode(params)}", status_code=303)


# ---------------------------------------------------------------------------
# /authorize
# ---------------------------------------------------------------------------


async def authorize(session: Any, request: Request, params: dict[str, Any]) -> RedirectResponse:
    client_id = str(params.get("client_id") or "")
    redirect_uri = params.get("redirect_uri")
    response_type = params.get("response_type")
    scope_value = str(params.get("scope") or "")
    requested_scopes = set(scope_value.split())

    client = await oidc_repo.get_client_by_public_id(session, client_id) if client_id else None
    if client is None or not client.enabled:
        await _audit(
            session,
            AuditAction.AUTH_OIDC_AUTHORIZE_DENIED,
            outcome=AuditOutcome.FAILURE,
            context={"reason": "unknown_or_disabled_client", "client_id": client_id},
        )
        raise OIDCAuthzError("invalid_request", "Unknown or disabled client")

    try:
        oidc_security.assert_redirect_registered(client, redirect_uri)
    except OIDCAuthzError as exc:
        await _audit(
            session,
            AuditAction.AUTH_OIDC_AUTHORIZE_DENIED,
            outcome=AuditOutcome.FAILURE,
            context={"reason": "unregistered_redirect", "client_id": client.client_id, "redirect_uri": str(redirect_uri)},
        )
        raise exc

    state = params.get("state") or None
    if response_type != "code":
        await _audit(session, AuditAction.AUTH_OIDC_AUTHORIZE_DENIED, outcome=AuditOutcome.FAILURE,
                     context={"reason": "unsupported_response_type", "client_id": client.client_id})
        return _error_redirect(str(redirect_uri), "unsupported_response_type", "Only response_type=code is supported", state)
    if "authorization_code" not in client.grant_types:
        await _audit(session, AuditAction.AUTH_OIDC_AUTHORIZE_DENIED, outcome=AuditOutcome.FAILURE,
                     context={"reason": "grant_not_allowed", "client_id": client.client_id})
        return _error_redirect(str(redirect_uri), "unauthorized_client", "Client may not use the authorization_code grant", state)
    if not requested_scopes.issubset(set(client.scopes)):
        await _audit(session, AuditAction.AUTH_OIDC_AUTHORIZE_DENIED, outcome=AuditOutcome.FAILURE,
                     context={"reason": "scope_escalation", "client_id": client.client_id, "requested": scope_value})
        return _error_redirect(str(redirect_uri), "invalid_scope", "Requested scope exceeds the registered grant", state)
    code_challenge = params.get("code_challenge")
    challenge_method = params.get("code_challenge_method")
    if not code_challenge or challenge_method != "S256":
        await _audit(session, AuditAction.AUTH_OIDC_AUTHORIZE_DENIED, outcome=AuditOutcome.FAILURE,
                     context={"reason": "pkce_missing_or_downgraded", "client_id": client.client_id})
        return _error_redirect(str(redirect_uri), "invalid_request", "PKCE with S256 is required (OAuth 2.1)", state)
    prompt_value = params.get("prompt") or ""
    response_mode = params.get("response_mode")
    max_age_raw = params.get("max_age")

    prompt_actions = set(prompt_value.split())
    if "none" in prompt_actions and prompt_actions & {"login", "consent", "select_account"}:
        await _audit(session, AuditAction.AUTH_OIDC_AUTHORIZE_DENIED, outcome=AuditOutcome.FAILURE,
                     context={"reason": "prompt_none_combined", "client_id": client.client_id})
        return _error_redirect(str(redirect_uri), "invalid_request", "prompt=none cannot be combined with other prompt values", state)
    if prompt_actions - {"none", "login", "consent", "select_account"}:
        await _audit(session, AuditAction.AUTH_OIDC_AUTHORIZE_DENIED, outcome=AuditOutcome.FAILURE,
                     context={"reason": "unsupported_prompt", "client_id": client.client_id, "prompt": prompt_value})
        return _error_redirect(str(redirect_uri), "invalid_request", "unsupported prompt value(s)", state)
    if response_mode and response_mode not in ("query", "fragment"):
        await _audit(session, AuditAction.AUTH_OIDC_AUTHORIZE_DENIED, outcome=AuditOutcome.FAILURE,
                     context={"reason": "unsupported_response_mode", "client_id": client.client_id})
        return _error_redirect(str(redirect_uri), "invalid_request", "response_mode must be query or fragment", state)
    if max_age_raw is not None:
        try:
            max_age = int(max_age_raw)
        except (TypeError, ValueError):
            await _audit(session, AuditAction.AUTH_OIDC_AUTHORIZE_DENIED, outcome=AuditOutcome.FAILURE,
                         context={"reason": "invalid_max_age", "client_id": client.client_id})
            return _error_redirect(str(redirect_uri), "invalid_request", "max_age must be integer seconds", state)
        if max_age < 0:
            await _audit(session, AuditAction.AUTH_OIDC_AUTHORIZE_DENIED, outcome=AuditOutcome.FAILURE,
                         context={"reason": "invalid_max_age", "client_id": client.client_id})
            return _error_redirect(str(redirect_uri), "invalid_request", "max_age must be non-negative", state)
    else:
        max_age = None

    pending: dict[str, Any] = {
        "client_id": client.client_id,
        "redirect_uri": str(redirect_uri),
        "scope": scope_value,
        "code_challenge": code_challenge,
        "code_challenge_method": challenge_method,
        "nonce": params.get("nonce") or None,
        "state": state,
        "prompt_none": "none" in prompt_actions,
        "force_login": "login" in prompt_actions,
        "max_age": max_age,
        "response_mode": response_mode or "query",
    }

    user: User | None = None
    user_payload: dict[str, Any] | None = None
    if not pending["force_login"]:
        user, user_payload = await _resolve_optional_user(session, request)

    if user is not None and user_payload:
        iat = float(user_payload.get("iat", 0))
        if pending["max_age"] is not None and (utc_now().timestamp() - iat) > pending["max_age"]:
            pending["force_login"] = True
            user, user_payload = None, None

    if user is None or pending["force_login"]:
        if pending["prompt_none"]:
            required = "login_required" if user is None else "interaction_required"
            await _audit(session, AuditAction.AUTH_OIDC_AUTHORIZE_DENIED, outcome=AuditOutcome.FAILURE,
                         context={"reason": f"prompt_none_{required}", "client_id": client.client_id})
            return _error_redirect(str(redirect_uri), required, "prompt=none forbids interaction", state)
        request.session[_PENDING_GRANT_KEY] = pending
        login_url = settings.SWX_OIDC_LOGIN_URL
        next_url = quote(str(request.url), safe="")
        separator = "&" if "?" in login_url else "?"
        return RedirectResponse(f"{login_url}{separator}next={next_url}", status_code=303)

    pending["auth_time"] = user_payload.get("iat") if user_payload else None
    return await _issue_code_and_redirect(session, request, user, pending)


async def complete_authorize(session: Any, request: Request, user: User) -> RedirectResponse:
    """Resume a pending authorization after authentication (IdP app login flow)."""
    pending = request.session.get(_PENDING_GRANT_KEY)
    if not pending:
        raise OIDCAuthzError("invalid_request", "No pending authorization for this session")
    _user, user_payload = await _resolve_optional_user(session, request)
    if user_payload and user_payload.get("iat"):
        pending["auth_time"] = user_payload["iat"]
    return await _issue_code_and_redirect(session, request, user, pending)


async def _issue_code_and_redirect(session: Any, request: Request, user: User, pending: dict[str, Any]) -> RedirectResponse:
    client = await oidc_repo.get_client_by_public_id(session, pending["client_id"])
    if client is None or not client.enabled:
        request.session.pop(_PENDING_GRANT_KEY, None)
        await _audit(session, AuditAction.AUTH_OIDC_AUTHORIZE_DENIED, outcome=AuditOutcome.FAILURE,
                     context={"reason": "client_disabled_mid_flow", "client_id": pending["client_id"]})
        raise OIDCAuthzError("invalid_request", "Client is no longer available")

    # Identity verification gate (v2.31, SWX_IDENTITY_REQUIRED_VERIFICATIONS):
    # fail-closed — the flow issues only once the required channels are verified.
    from swx_core.auth.oidc_provider.identity_verification import gate_error_for_user

    gate = gate_error_for_user(user)
    if gate is not None:
        error_code, description = gate
        await _audit(
            session,
            AuditAction.AUTH_OIDC_AUTHORIZE_DENIED,
            outcome=AuditOutcome.FAILURE,
            context={"reason": "identity_verification_incomplete", "client_id": client.client_id, "detail": description},
            actor_id=str(user.id),
        )
        if pending.get("prompt_none"):
            raise OIDCAuthzError("interaction_required", description, status_code=400) from None
        request.session[_PENDING_GRANT_KEY] = {**pending, "verification_required": True}
        login_url = settings.SWX_OIDC_LOGIN_URL
        next_url = quote(str(request.url), safe="")
        separator = "&" if "?" in login_url else "?"
        return RedirectResponse(f"{login_url}{separator}next={next_url}", status_code=303)

    auth_time_value = pending.get("auth_time")
    auth_time: datetime | None = (
        datetime.fromtimestamp(auth_time_value, tz=utc_now().tzinfo) if auth_time_value else None
    )
    amr = request.session.get("swx_amr") or _DEFAULT_AMR
    acr = _ACR_MFA if "mfa" in amr else _ACR_PWD

    code = secrets.token_urlsafe(32)
    await oidc_repo.create_grant_code(session, {
        "code_hash": oidc_tokens.sha256_hex(code),
        "client_id": client.client_id,
        "user_id": user.id,
        "redirect_uri": pending["redirect_uri"],
        "scope": pending["scope"],
        "code_challenge": pending.get("code_challenge"),
        "code_challenge_method": pending.get("code_challenge_method"),
        "nonce": pending.get("nonce"),
        "auth_time": auth_time,
        "acr": acr,
        "amr": amr,
        "expires_at": utc_now() + timedelta(seconds=settings.SWX_OIDC_CODE_TTL_SECONDS),
    })

    await oidc_repo.upsert_consent(session, user_id=user.id, client_id=client.client_id, scope=pending["scope"])
    await _audit(
        session,
        AuditAction.AUTH_CONSENT_GRANTED,
        context={"scope": pending["scope"]},
        actor_id=str(user.id),
        resource_id=client.client_id,
        resource_type="oidc_client",
    )

    request.session.pop(_PENDING_GRANT_KEY, None)
    redirect_params: dict[str, str] = {"code": code}
    if pending.get("state") is not None:
        redirect_params["state"] = str(pending["state"])
    if pending.get("response_mode") == "fragment":
        return RedirectResponse(f"{pending['redirect_uri']}#{urlencode(redirect_params)}", status_code=303)
    return RedirectResponse(f"{pending['redirect_uri']}?{urlencode(redirect_params)}", status_code=303)


# ---------------------------------------------------------------------------
# /token
# ---------------------------------------------------------------------------


async def token(session: Any, request: Request, form: dict[str, Any]) -> dict[str, Any]:
    grant_type = str(form.get("grant_type") or "")
    client: Any = None
    try:
        client = await oidc_security.authenticate_client(session, request, form)
        if grant_type == "authorization_code":
            return await _authorization_code_grant(session, request, client, form)
        if grant_type == "refresh_token":
            return await _refresh_token_grant(session, request, client, form)
        if grant_type == "client_credentials":
            return await _client_credentials_grant(session, request, client, form)
        raise OIDCAuthzError("unsupported_grant_type", f"Grant type {grant_type!r} is not supported")
    except OIDCAuthzError as exc:
        denial_context: dict[str, Any] = {
            "error": exc.error,
            "grant_type": grant_type,
            "client_id": client.client_id if client else None,
        }
        denial_context.update(getattr(exc, "context", None) or {})
        await _audit(
            session,
            AuditAction.AUTH_OIDC_TOKEN_DENIED,
            outcome=AuditOutcome.FAILURE,
            context=denial_context,
            actor_id=client.client_id if client else None,
            resource_id=client.client_id if client else None,
            resource_type="oidc_client",
        )
        raise exc
    except oidc_tokens.OIDCSigningUnavailable as exc:
        await _audit(
            session,
            AuditAction.AUTH_OIDC_TOKEN_DENIED,
            outcome=AuditOutcome.FAILURE,
            context={"error": "temporarily_unavailable", "grant_type": grant_type, "client_id": client.client_id if client else None},
            actor_id=client.client_id if client else None,
            resource_id=client.client_id if client else None,
            resource_type="oidc_client",
        )
        raise


async def _authorization_code_grant(session: Any, request: Request, client: Any, form: dict[str, Any]) -> dict[str, Any]:
    code = str(form.get("code") or "")
    if not code:
        raise OIDCAuthzError("invalid_request", "code is required")

    row = await oidc_repo.get_grant_code_by_hash(session, oidc_tokens.sha256_hex(code))
    if row is None or row.client_id != client.client_id:
        raise OIDCAuthzError("invalid_grant", "Unknown authorization code")
    if row.expires_at < utc_now():
        raise OIDCAuthzError("invalid_grant", "Authorization code has expired")
    if form.get("redirect_uri") != row.redirect_uri:
        _ = await oidc_repo.consume_grant_code(session, row.id)
        raise OIDCAuthzError("invalid_grant", "redirect_uri does not match the authorization request")
    if not await oidc_repo.consume_grant_code(session, row.id):
        raise OIDCAuthzError("invalid_grant", "Authorization code already redeemed (replay refused)")
    if row.code_challenge:
        oidc_security.verify_pkce(form.get("code_verifier"), row.code_challenge, row.code_challenge_method or "")

    user = await session.get(User, row.user_id)
    if user is None or not user.is_active:
        raise OIDCAuthzError("invalid_grant", "Grant subject is no longer available")

    issuer = derive_issuer(request)
    access = await oidc_tokens.mint_access_token(
        session,
        issuer=issuer,
        subject=str(user.id),
        client_id=client.client_id,
        scope=row.scope,
        expires_delta=timedelta(seconds=client.access_token_ttl_seconds),
        extra_claims={
            "auth_time": row.auth_time.timestamp() if row.auth_time else None,
            "acr": row.acr,
            "amr": row.amr,
        },
    )

    id_token = None
    if "openid" in row.scope.split():
        id_token = await oidc_tokens.mint_id_token(
            session,
            issuer=issuer,
            subject=str(user.id),
            client_id=client.client_id,
            expires_delta=timedelta(seconds=client.id_token_ttl_seconds),
            nonce=row.nonce,
            auth_time=row.auth_time,
            acr=row.acr,
            amr=row.amr,
            access_token=access,
        )

    response: dict[str, Any] = {
        "access_token": access,
        "token_type": oidc_tokens.TOKEN_TYPE_BEARER,
        "expires_in": client.access_token_ttl_seconds,
        "scope": row.scope,
    }
    if "offline_access" in row.scope.split():
        refresh_value, _refresh_row = await oidc_tokens.mint_refresh_token(
            session,
            family_id=uuid.uuid4(),
            client_id=client.client_id,
            user_id=user.id,
            scope=row.scope,
            auth_time=row.auth_time,
            expires_delta=timedelta(seconds=client.refresh_token_ttl_seconds),
        )
        response["refresh_token"] = refresh_value
    if id_token is not None:
        response["id_token"] = id_token

    await _audit(
        session,
        AuditAction.AUTH_TOKEN_ISSUED,
        context={"grant_type": "authorization_code", "scope": row.scope},
        actor_id=str(user.id),
        resource_id=client.client_id,
        resource_type="oidc_client",
    )
    return response


async def _revoke_family_for_reuse(session: Any, row: Any) -> None:
    revoked = await oidc_repo.revoke_family(session, row.family_id)
    await _audit(
        session,
        AuditAction.AUTH_TOKEN_FAMILY_REVOKED,
        outcome=AuditOutcome.FAILURE,
        context={"reason": "refresh_token_reuse", "family_revoked": revoked, "family_id": str(row.family_id)},
        actor_id=str(row.user_id),
        resource_id=row.client_id,
        resource_type="oidc_client",
    )
    await _audit(
        session,
        AuditAction.AUTH_OIDC_TOKEN_DENIED,
        outcome=AuditOutcome.FAILURE,
        context={"error": "invalid_grant", "reason": "refresh_token_reuse"},
        actor_id=str(row.user_id),
    )


async def _refresh_token_grant(session: Any, request: Request, client: Any, form: dict[str, Any]) -> dict[str, Any]:
    refresh_value = str(form.get("refresh_token") or "")
    if not refresh_value:
        raise OIDCAuthzError("invalid_request", "refresh_token is required")

    row = await oidc_repo.get_refresh_token_by_hash(session, oidc_tokens.sha256_hex(refresh_value))
    if row is None or row.client_id != client.client_id:
        raise OIDCAuthzError("invalid_grant", "Unknown refresh token")
    if row.expires_at < utc_now():
        raise OIDCAuthzError("invalid_grant", "Refresh token has expired")
    if row.status != REFRESH_STATUS_ACTIVE:
        await _revoke_family_for_reuse(session, row)
        raise OIDCAuthzError("invalid_grant", "Refresh token reuse detected; token family revoked")

    new_refresh, new_hash = oidc_tokens.generate_refresh_value()
    allowed_scopes = set(client.scopes)
    requested_scopes = set(row.scope.split())
    if not requested_scopes.issubset(allowed_scopes):
        requested_scopes &= allowed_scopes
    if not requested_scopes:
        raise OIDCAuthzError("invalid_scope", "no requested scope remains registered for this client")
    effective_scope = " ".join(sorted(requested_scopes))
    rotated = await oidc_repo.rotate_refresh_tokens(
        session,
        old_id=row.id,
        new_data={
            "family_id": row.family_id,
            "token_hash": new_hash,
            "client_id": row.client_id,
            "user_id": row.user_id,
            "scope": effective_scope,
            "status": REFRESH_STATUS_ACTIVE,
            "auth_time": row.auth_time,
            "expires_at": utc_now() + timedelta(seconds=client.refresh_token_ttl_seconds),
        },
    )
    if rotated is None:
        await _revoke_family_for_reuse(session, row)
        raise OIDCAuthzError("invalid_grant", "Refresh token reuse detected; token family revoked")

    issuer = derive_issuer(request)
    access = await oidc_tokens.mint_access_token(
        session,
        issuer=issuer,
        subject=str(row.user_id),
        client_id=row.client_id,
        scope=effective_scope,
        expires_delta=timedelta(seconds=client.access_token_ttl_seconds),
        extra_claims={"auth_time": row.auth_time.timestamp() if row.auth_time else None},
    )

    id_token = None
    if "openid" in effective_scope.split():
        id_token = await oidc_tokens.mint_id_token(
            session,
            issuer=issuer,
            subject=str(row.user_id),
            client_id=row.client_id,
            expires_delta=timedelta(seconds=client.id_token_ttl_seconds),
            auth_time=row.auth_time,
            access_token=access,
        )

    await _audit(
        session,
        AuditAction.AUTH_TOKEN_ISSUED,
        context={"grant_type": "refresh_token", "scope": effective_scope},
        actor_id=str(row.user_id),
        resource_id=row.client_id,
        resource_type="oidc_client",
    )

    response: dict[str, Any] = {
        "access_token": access,
        "token_type": oidc_tokens.TOKEN_TYPE_BEARER,
        "expires_in": client.access_token_ttl_seconds,
        "refresh_token": new_refresh,
        "scope": effective_scope,
    }
    if id_token is not None:
        response["id_token"] = id_token
    return response


async def _client_credentials_grant(session: Any, request: Request, client: Any, form: dict[str, Any]) -> dict[str, Any]:
    if client.client_secret_hash is None:
        raise OIDCAuthzError("unauthorized_client", "client_credentials requires a confidential client")
    if not client.is_first_party:
        raise OIDCAuthzError("unauthorized_client", "client_credentials is restricted to first-party clients")

    requested = set(str(form.get("scope") or "").split())
    allowed = set(client.scopes) - {"openid", "offline_access"}
    if requested - allowed:
        raise OIDCAuthzError("invalid_scope", "Requested scope exceeds the registered grant")
    scope = " ".join(sorted(requested & allowed)) if requested else " ".join(sorted(allowed))

    access = await oidc_tokens.mint_access_token(
        session,
        issuer=derive_issuer(request),
        subject=client.client_id,
        client_id=client.client_id,
        scope=scope,
        expires_delta=timedelta(seconds=client.access_token_ttl_seconds),
    )

    await _audit(
        session,
        AuditAction.AUTH_TOKEN_ISSUED,
        context={"grant_type": "client_credentials", "scope": scope},
        actor_id=client.client_id,
        resource_id=client.client_id,
        resource_type="oidc_client",
    )

    return {
        "access_token": access,
        "token_type": oidc_tokens.TOKEN_TYPE_BEARER,
        "expires_in": client.access_token_ttl_seconds,
        "scope": scope,
    }


# ---------------------------------------------------------------------------
# /revoke (RFC 7009)
# ---------------------------------------------------------------------------


async def revoke(session: Any, request: Request, form: dict[str, Any]) -> dict[str, bool]:
    client = await oidc_security.authenticate_client(session, request, form)
    token_value = str(form.get("token") or "")
    if not token_value:
        raise OIDCAuthzError("invalid_request", "token is required")

    if "." in token_value:
        # Access-token revocation: unknown/invalid tokens yield a silent 200 —
        # RFC 7009 §2.2 mandates not revealing token validity (anti-enumeration).
        payload: dict[str, Any] | None = None
        try:
            payload = await oidc_tokens.verify_oidc_access_token(session, token_value)
        except Exception:
            payload = None
        if payload is not None and payload.get("client_id") == client.client_id:
            jti = payload.get("jti")
            exp = payload.get("exp")
            ttl = max(1, int(float(exp) - utc_now().timestamp())) if exp else 60
            blacklist = _get_token_blacklist()
            if blacklist is not None and jti:
                await blacklist.revoke(jti, ttl)
            await _audit(
                session,
                AuditAction.AUTH_TOKEN_REVOKED,
                context={"token_kind": "access", "jti": jti},
                actor_id=client.client_id,
                resource_id=client.client_id,
                resource_type="oidc_client",
            )
        elif payload is not None:
            await _audit(
                session,
                AuditAction.AUTH_OIDC_TOKEN_DENIED,
                outcome=AuditOutcome.FAILURE,
                context={"path": "revoke", "reason": "cross_client_token", "client_id": client.client_id, "aud": payload.get("aud")},
                actor_id=client.client_id,
                resource_id=client.client_id,
                resource_type="oidc_client",
            )
    else:
        row = await oidc_repo.get_refresh_token_by_hash(session, oidc_tokens.sha256_hex(token_value))
        if row is not None and row.client_id == client.client_id:
            revoked = await oidc_repo.revoke_family(session, row.family_id)
            await _audit(
                session,
                AuditAction.AUTH_TOKEN_REVOKED,
                context={"token_kind": "refresh", "family_revoked": revoked},
                actor_id=str(row.user_id),
                resource_id=row.client_id,
                resource_type="oidc_client",
            )
        elif row is not None:
            await _audit(
                session,
                AuditAction.AUTH_OIDC_TOKEN_DENIED,
                outcome=AuditOutcome.FAILURE,
                context={"path": "revoke", "reason": "cross_client_revocation_attempt", "client_id": client.client_id},
                actor_id=client.client_id,
                resource_id=client.client_id,
                resource_type="oidc_client",
            )
    return {}


# ---------------------------------------------------------------------------
# /userinfo
# ---------------------------------------------------------------------------


async def userinfo(session: Any, request: Request) -> dict[str, Any]:
    """Audited wrapper: every userinfo refusal writes ``auth.oidc_token_denied``."""
    try:
        return await _userinfo_claims(session, request)
    except OIDCAuthzError as exc:
        await _audit(
            session,
            AuditAction.AUTH_OIDC_TOKEN_DENIED,
            outcome=AuditOutcome.FAILURE,
            context={"path": "userinfo", "error": exc.error},
        )
        raise


async def _userinfo_claims(session: Any, request: Request) -> dict[str, Any]:
    header = request.headers.get("Authorization", "")
    if not header.startswith("Bearer "):
        raise OIDCAuthzError("invalid_token", "Bearer access token required", status_code=401)
    try:
        payload = await oidc_tokens.verify_oidc_access_token(session, header[7:])
    except Exception:
        raise OIDCAuthzError("invalid_token", "Access token is invalid or expired", status_code=401) from None

    audience = payload.get("aud")
    client_id = (
        str(audience).removeprefix("oidc_client:")
        if isinstance(audience, str) and audience.startswith("oidc_client:")
        else None
    )
    if not client_id:
        raise OIDCAuthzError("invalid_token", "Access token audience is not an OIDC client", status_code=401)
    client = await oidc_repo.get_client_by_public_id(session, client_id)
    if client is None or not client.enabled:
        raise OIDCAuthzError("invalid_token", "Access token audience is not an active client", status_code=401)

    try:
        subject = uuid.UUID(str(payload.get("sub")))
    except ValueError:
        raise OIDCAuthzError("invalid_token", "Access token subject is not a user", status_code=401) from None
    user = await session.get(User, subject)
    if user is None or not user.is_active:
        raise OIDCAuthzError("invalid_token", "Access token subject is no longer active", status_code=401)

    scopes = set(str(payload.get("scope") or "").split())
    claims: dict[str, Any] = {"sub": str(user.id)}
    if "profile" in scopes and user.full_name:
        claims["name"] = user.full_name
    if "phone" in scopes:
        claims["phone"] = getattr(user, "phone", None)
        claims["phone_verified"] = getattr(user, "phone_verified_at", None) is not None
    return claims