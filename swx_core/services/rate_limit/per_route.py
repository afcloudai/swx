"""
Per-Route Rate Limit Configuration
-----------------------------------
Declare route-specific rate limits that override the plan-based defaults.

Two registration styles are supported:

1. **Decorator/dependency** on individual routes::

       from swx_core.services.rate_limit.per_route import rate_limit

       @router.post("/detect/public")
       @rate_limit("5/minute", namespace="detection:detect:public")
       async def detect_public(request: Request):
           ...

2. **Bulk registration** at app startup::

       from swx_core.services.rate_limit.per_route import route_limits

       route_limits.configure({
           "/api/detect/public": {"post": "5/minute"},
           "/api/search": {"get": "100/hour"},
       })

When a route has a per-route limit, it takes precedence over the
plan-based registry.  The override order is:

    per-route limit  >  database override  >  plan-based default
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

from fastapi import HTTPException, Request, status

from swx_core.services.rate_limit.enforce import (
    enforce_rate_limit,
    get_client_ip,
    parse_rate_limit,
)
from swx_core.services.rate_limit.rate_limiter import LimitWindow, get_rate_limiter
from swx_core.middleware.logging_middleware import logger


@dataclass
class _RouteLimitEntry:
    path: str
    method: str
    max_requests: int
    window_seconds: int


class RouteRateLimitConfig:
    """Registry for per-route rate limit overrides.

    Routes are matched by exact path string or compiled regex pattern.
    """

    def __init__(self) -> None:
        self._exact: Dict[str, Dict[str, _RouteLimitEntry]] = {}
        self._patterns: list[tuple[re.Pattern[str], Dict[str, _RouteLimitEntry]]] = []

    def configure(
        self,
        mapping: Dict[str, Dict[str, str]],
    ) -> "RouteRateLimitConfig":
        """Register per-route limits from a config dict.

        Args:
            mapping: ``{path: {method: limit_string}}`` where
                *path* is a URL pattern (supports ``{param}`` wildcards)
                and *method* is an HTTP verb in lowercase.
                *limit_string* follows the ``"5/minute"`` format.

        Returns:
            ``self``, for chaining.
        """
        for path, method_limits in mapping.items():
            for method, limit_str in method_limits.items():
                max_requests, window_seconds = parse_rate_limit(limit_str)
                entry = _RouteLimitEntry(
                    path=path,
                    method=method.lower(),
                    max_requests=max_requests,
                    window_seconds=window_seconds,
                )
                if "{" in path or "*" in path:
                    pattern = re.compile(
                        re.sub(r"\{[^}]+\}", r"[^/]+", path).replace("*", ".*")
                    )
                    bucket_entry = next(
                        (m for p, m in self._patterns if p.pattern == pattern.pattern),
                        None,
                    )
                    if bucket_entry is None:
                        bucket_entry = {}
                        self._patterns.append((pattern, bucket_entry))
                    bucket_entry[method.lower()] = entry
                else:
                    self._exact.setdefault(path, {})[method.lower()] = entry
        return self

    def lookup(self, path: str, method: str) -> Optional[_RouteLimitEntry]:
        """Find a per-route limit entry for the given path and method.

        Exact matches take priority over pattern matches.
        """
        method_lower = method.lower()
        exact_match = self._exact.get(path, {}).get(method_lower)
        if exact_match:
            return exact_match

        for pattern, method_map in self._patterns:
            if pattern.fullmatch(path):
                return method_map.get(method_lower)
        return None

    def __len__(self) -> int:
        count = sum(len(m) for m in self._exact.values())
        count += sum(len(m) for _, m in self._patterns)
        return count


route_limits = RouteRateLimitConfig()


def rate_limit(
    limit_string: str,
    *,
    namespace: str,
) -> Any:
    """FastAPI dependency that enforces a per-route rate limit.

    Args:
        limit_string: Human-readable limit like ``"5/minute"`` or ``"100/hour"``.
        namespace: Application-specific rate limit namespace used as the
            Redis key prefix (e.g. ``"detection:detect:public"``).

    Returns:
        An async dependency callable suitable for ``Depends()``.
    """

    max_requests, window_seconds = parse_rate_limit(limit_string)

    window = LimitWindow.MINUTE
    if window_seconds >= 86400:
        window = LimitWindow.DAY
    elif window_seconds >= 3600:
        window = LimitWindow.HOUR

    async def _dependency(request: Request) -> int:
        limiter = get_rate_limiter()

        from swx_core.services.rate_limit.enforce import _resolve_actor
        actor_type, actor_id, _ = _resolve_actor(request)

        redis_key = f"rate_limit:{actor_type}:{actor_id}:{namespace}:{window.value}"
        result = await limiter.check_limit(redis_key, max_requests, window)

        if not result.allowed:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Rate limit exceeded for {namespace}",
                headers={
                    "Retry-After": str(result.retry_after or window_seconds),
                    "X-RateLimit-Limit": str(result.limit),
                    "X-RateLimit-Remaining": "0",
                    "X-RateLimit-Reset": str(int(result.reset_at.timestamp())),
                },
            )

        return result.remaining

    return _dependency