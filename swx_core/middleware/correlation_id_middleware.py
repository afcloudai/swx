"""
Correlation ID Middleware
-------------------------
Generates a UUID correlation ID for each request when ``X-Correlation-ID``
is not provided by the client.  The ID is stored in
``request.state.correlation_id`` and injected into the ASGI scope so
downstream middleware, loggers, and SSE/WS frames can reference it.

This middleware should be added **before** ``LoggingMiddleware`` in the
canonical stack so that every log line includes the correlation ID.

Behaviour
~~~~~~~~~

1.  If the incoming request includes ``X-Correlation-ID``, use it as-is.
2.  Otherwise, generate ``uuid4()`` and store it.
3.  Store the ID in ``scope["state"]["correlation_id"]`` (dict) or
    ``scope.state.correlation_id`` (namespace) depending on the state type.
4.  Inject ``X-Correlation-ID`` into the *response* headers so clients
    can echo it back.
5.  The ``LoggingMiddleware`` (which already reads ``correlation_id``
    from scope state) will automatically include it in log output —
    no changes needed there.
"""

from __future__ import annotations

import re
import uuid
from typing import Callable

from starlette.types import ASGIApp, Message, Receive, Scope, Send


_HEADER = b"x-correlation-id"
_HEADER_STR = "x-correlation-id"
_CORRELATION_ID_RE = re.compile(r"^[a-zA-Z0-9._\-]{1,128}$")
_MAX_CORRELATION_ID_LEN = 128


def _extract_header(headers: list[tuple[bytes, bytes]], name: bytes) -> str | None:
    for k, v in headers:
        if k.lower() == name:
            return v.decode("latin-1")
    return None


def _set_state(state: object, key: str, value: str) -> None:
    if isinstance(state, dict):
        state[key] = value
    else:
        setattr(state, key, value)


def _get_state(state: object, key: str) -> str | None:
    if isinstance(state, dict):
        val = state.get(key)
        return str(val) if val is not None else None
    val = getattr(state, key, None)
    return str(val) if val is not None else None


class CorrelationIdMiddleware:
    """Pure-ASGI middleware that ensures every request has a correlation ID.

    If ``X-Correlation-ID`` is present on the incoming request, it is
    preserved.  Otherwise a ``uuid4()`` is generated.  The ID is stored
    in ``scope["state"]`` and injected into the response headers.
    """

    def __init__(self, app: ASGIApp, header: str = _HEADER_STR) -> None:
        self.app = app
        self.header = header
        self.header_bytes = header.encode("latin-1")

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return

        headers_list: list[tuple[bytes, bytes]] = scope.get("headers", [])
        correlation_id = _extract_header(headers_list, _HEADER)

        if not correlation_id or len(correlation_id) > _MAX_CORRELATION_ID_LEN or not _CORRELATION_ID_RE.match(correlation_id):
            correlation_id = str(uuid.uuid4())
            headers_list = list(scope.get("headers", []))
            headers_list.append((_HEADER, correlation_id.encode("latin-1")))
            scope["headers"] = headers_list

        state = scope.setdefault("state", {})
        _set_state(state, "correlation_id", correlation_id)

        async def send_with_correlation(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                headers.append((self.header_bytes, correlation_id.encode("latin-1")))
                message = {**message, "headers": headers}
            await send(message)

        await self.app(scope, receive, send_with_correlation)