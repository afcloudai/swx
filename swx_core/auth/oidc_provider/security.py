# pyright: reportMissingImports=false, reportAny=false, reportExplicitAny=false, reportUnknownMemberType=false, reportUnknownArgumentType=false, reportUnusedCallResult=false, reportAttributeAccessIssue=false

"""
OIDC security primitives (SWX-IDM-001, D-3/D-6)
-----------------------------------------------
Fail-closed rules enforced here:

- **PKCE**: S256 is the only accepted ``code_challenge_method`` — ``plain``
  requests are refused outright (downgrade protection). Verifiers must match
  the RFC 7636 charset/length; challenges are compared constant-time.
- **redirect_uri**: exact match against the client's registered list — no
  normalization, no wildcards, no prefixes.
- **client authentication**: HTTP Basic or form body only. A client secret
  presented in the query string is refused before any other check.
"""

import base64
import hashlib
import hmac
import re
from typing import Any

from fastapi import Request

from swx_core.auth.oidc_provider import repositories as oidc_repo
from swx_core.auth.oidc_provider.models import OIDCClient
from swx_core.security.password_security import get_password_hash, verify_password

SUPPORTED_CODE_CHALLENGE_METHODS = frozenset({"S256"})

_VERIFIER_PATTERN = re.compile(r"^[A-Za-z0-9\-._~]{43,128}$")

_DUMMY_SECRET_HASH: str | None = None


async def _equalize_bcrypt_timing(performed_real_verify: bool) -> None:
    """Equalize bcrypt timing between unknown-client and known-client refusals.

    Without this, an attacker distinguishing "unknown client_id" (fast skip) from
    "known client_id, bad secret" (bcrypt) could enumerate registered clients.
    """
    global _DUMMY_SECRET_HASH
    if performed_real_verify:
        return
    if _DUMMY_SECRET_HASH is None:
        _DUMMY_SECRET_HASH = await get_password_hash("timing-equalizer")
    await verify_password("timing-equalizer", _DUMMY_SECRET_HASH)


class OIDCAuthzError(Exception):
    """RFC 6749 §5.2 protocol error. ``status_code`` distinguishes 400 vs 401."""

    def __init__(self, error: str, description: str, status_code: int = 400):
        super().__init__(f"{error}: {description}")
        self.error = error
        self.description = description
        self.status_code = status_code


def s256_challenge(code_verifier: str) -> str:
    digest = hashlib.sha256(code_verifier.encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


def verify_pkce(code_verifier: str | None, code_challenge: str, code_challenge_method: str) -> None:
    if not code_verifier:
        raise OIDCAuthzError("invalid_request", "code_verifier is required")
    if not _VERIFIER_PATTERN.match(code_verifier):
        raise OIDCAuthzError("invalid_request", "code_verifier must be 43-128 chars of [A-Za-z0-9-._~]")
    if code_challenge_method not in SUPPORTED_CODE_CHALLENGE_METHODS:
        raise OIDCAuthzError("invalid_request", "code_challenge_method must be S256")
    if not hmac.compare_digest(s256_challenge(code_verifier), code_challenge):
        raise OIDCAuthzError("invalid_grant", "PKCE verification failed")


def assert_redirect_registered(client: OIDCClient, redirect_uri: str | None) -> None:
    """Exact membership in the registered list; unknown URIs must never be redirected to."""
    if not redirect_uri or redirect_uri not in client.redirect_uris:
        raise OIDCAuthzError("invalid_request", "redirect_uri is not registered for this client")


def _decode_basic_auth(request: Request) -> tuple[str, str] | None:
    header = request.headers.get("Authorization", "")
    if not header.startswith("Basic "):
        return None
    try:
        raw = base64.b64decode(header[6:].strip()).decode()
    except Exception:
        raise OIDCAuthzError("invalid_client", "Malformed Basic authorization header", status_code=401)
    client_id, _, client_secret = raw.rpartition(":")
    if not client_id:
        raise OIDCAuthzError("invalid_client", "Malformed Basic authorization header", status_code=401)
    return client_id, client_secret


def extract_client_credentials(request: Request, form: dict[str, Any]) -> list[tuple[str, str | None]]:
    """Candidate credentials from Basic header and/or the body (never the query string).

    RFC 6749 §2.3: when credentials are transmitted in more than one way and
    they differ, the request MUST be rejected — a mixed Basic(clientA) +
    body(clientB) request is refused before any lookup.
    """
    if request.query_params.get("client_secret"):
        raise OIDCAuthzError("invalid_request", "client_secret must not be sent in the query string")

    basic = _decode_basic_auth(request)
    body_id = form.get("client_id")
    if basic is not None and body_id:
        raise OIDCAuthzError(
            "invalid_request",
            "multiple client authentication methods used (Basic header + body credentials)",
            status_code=400,
        )

    candidates: list[tuple[str, str | None]] = []
    if basic is not None:
        candidates.append(basic)

    if body_id:
        body_secret = form.get("client_secret")
        if body_secret:
            candidates.append((str(body_id), str(body_secret)))
        else:
            candidates.append((str(body_id), None))

    if not candidates:
        raise OIDCAuthzError("invalid_client", "Client authentication required", status_code=401)
    return candidates


async def authenticate_client(session: Any, request: Request, form: dict[str, Any]) -> OIDCClient:
    """Authenticate a confidential (Basic/body secret) or public (secretless) client.

    Refusals are deliberately terse (RFC 6749 §5.3.2: the token endpoint must
    not give an attacker diagnostic detail) — every rejection is uniform.
    Raises ``OIDCAuthzError('invalid_client', …, 401)`` on any credential
    mismatch, and 400 ``invalid_request`` for a query-string secret or mixed
    authentication methods.
    """
    candidates = extract_client_credentials(request, form)
    performed_real_verify = False
    for client_id, client_secret in candidates:
        client = await oidc_repo.get_client_by_public_id(session, client_id)
        if client is None:
            continue

        if not client.enabled:
            continue

        if client_secret is None:
            if client.client_secret_hash is not None:
                continue
            return client  # public client, secretless body

        if client.client_secret_hash is None:
            continue
        if not await verify_password(client_secret, client.client_secret_hash):
            performed_real_verify = True
            continue
        return client

    await _equalize_bcrypt_timing(performed_real_verify)
    refusal = OIDCAuthzError("invalid_client", "Client authentication failed", status_code=401)
    refusal.context = {"attempted_client_ids": [client_id for client_id, _ in candidates]}
    raise refusal