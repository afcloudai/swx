"""
Rate Limiter
------------
Redis-backed rate limiting with token bucket and sliding window algorithms.

Features:
- Identity-aware limits
- Billing-aware limits
- Feature-aware limits
- Endpoint-aware limits
- Atomic operations
- Fail-closed behavior
"""

import time
from typing import Optional, Union
from datetime import datetime, timezone
from enum import Enum
from swx_core.utils.time import utc_now

from swx_core.middleware.logging_middleware import logger

class LimitWindow(str, Enum):
    """Rate limit time windows."""
    MINUTE = "1m"
    HOUR = "1h"
    DAY = "24h"

_WINDOW_SECONDS: dict[LimitWindow, int] = {
    LimitWindow.MINUTE: 60,
    LimitWindow.HOUR: 3600,
    LimitWindow.DAY: 86400,
}

_INT_TO_WINDOW: dict[int, LimitWindow] = {
    60: LimitWindow.MINUTE,
    3600: LimitWindow.HOUR,
    86400: LimitWindow.DAY,
}


class RateLimitResult:
    """Result of a rate limit check."""
    def __init__(
        self,
        allowed: bool,
        limit: int,
        remaining: int,
        reset_at: datetime,
        retry_after: Optional[int] = None
    ):
        self.allowed = allowed
        self.limit = limit
        self.remaining = remaining
        self.reset_at = reset_at
        self.retry_after = retry_after


def _normalise_window(window: Union[LimitWindow, int, str]) -> tuple[LimitWindow, int]:
    """Convert a window value to (LimitWindow, seconds).

    Accepts a :class:`LimitWindow` enum member, any string-valued enum of the
    same shape, or the raw strings ``"1m"/"1h"/"24h"``, or raw integers
    (60, 3600, 86400). String-shaped inputs are normalised by **value**, not
    class identity: the dynamic module loader reloads this module at boot,
    which rebinds LimitWindow to a fresh class while import-time bindings
    elsewhere keep the stale one — a class-identity ``isinstance`` would then
    raise for every request and break enforcement.

    Raises:
        ValueError: If *window* is an unrecognised string or integer.
    """
    if isinstance(window, LimitWindow):
        return window, _WINDOW_SECONDS[window]

    if isinstance(window, bool):
        raise TypeError("window must be LimitWindow, int, or str")

    if isinstance(window, int):
        enum_val = _INT_TO_WINDOW.get(window)
        if enum_val is not None:
            return enum_val, window
        raise ValueError(
            f"Unsupported rate-limit window: {window}s. "
            f"Expected one of {sorted(_INT_TO_WINDOW)} seconds, "
            f"or a LimitWindow enum member."
        )

    if isinstance(window, str):
        try:
            member = LimitWindow(window)
        except ValueError as exc:
            raise ValueError(
                f"Unsupported rate-limit window string: {window!r}. "
                f"Expected one of {[m.value for m in LimitWindow]}."
            ) from exc
        return member, _WINDOW_SECONDS[member]

    raise TypeError(
        f"window must be LimitWindow, int, or str, got {type(window).__name__}"
    )


class RateLimiter:
    """
    Redis-backed rate limiter using sliding window algorithm.
    
    Uses atomic Redis operations to ensure thread-safety across
    multiple workers/instances.
    """
    
    def __init__(self, redis_client=None):
        """
        Initialize rate limiter.
        
        Args:
            redis_client: Redis client (aioredis or redis.asyncio)
        """
        self.redis = redis_client
        self._window_seconds = _WINDOW_SECONDS

    def _fail_result(self, limit: int, window: Union[LimitWindow, int]) -> RateLimitResult:
        """Return a result based on RATE_LIMIT_FAIL_OPEN setting."""
        from swx_core.config.settings import settings

        _, window_secs = _normalise_window(window)
        now = utc_now()

        if getattr(settings, "RATE_LIMIT_FAIL_OPEN", False):
            logger.warning("Redis unavailable, rate limit check allowed (fail-open)")
            return RateLimitResult(
                allowed=True,
                limit=limit,
                remaining=max(0, limit - 1),
                reset_at=now,
                retry_after=None,
            )

        logger.warning("Redis unavailable, rate limit check denied (fail-closed)")
        return RateLimitResult(
            allowed=False,
            limit=limit,
            remaining=0,
            reset_at=now,
            retry_after=window_secs,
        )
    
    async def check_limit(
        self,
        key: str,
        limit: int,
        window: Union[LimitWindow, int] = LimitWindow.MINUTE
    ) -> RateLimitResult:
        """
        Check if request is within rate limit.
        
        Uses sliding window algorithm with atomic Redis operations.
        
        Args:
            key: Redis key for this limit (e.g., "rate_limit:user:123:api_requests:read:1m")
            limit: Maximum requests allowed in window
            window: Time window — :class:`LimitWindow` enum or raw seconds
                (60, 3600, 86400).
        
        Returns:
            RateLimitResult with allowed status and metadata
        """
        if not self.redis:
            return self._fail_result(limit, window)
        
        try:
            window_enum, window_seconds = _normalise_window(window)
            now = time.time()
            window_start = now - window_seconds
            
            # Use sliding window: count requests in current window
            # Redis key stores sorted set with timestamps as scores
            pipe = self.redis.pipeline()
            
            # Remove expired entries (older than window)
            pipe.zremrangebyscore(key, 0, window_start)
            
            # Count current requests in window
            pipe.zcard(key)
            
            # Add current request
            pipe.zadd(key, {str(now): now})
            
            # Set expiration
            pipe.expire(key, window_seconds)
            
            _, current_count, _, _ = await pipe.execute()
            
            # Check if limit exceeded
            allowed = current_count < limit
            remaining = max(0, limit - current_count - 1) if allowed else 0
            
            # Calculate reset time
            reset_at = datetime.fromtimestamp(now + window_seconds, tz=timezone.utc)
            retry_after = int(window_seconds) if not allowed else None
            
            return RateLimitResult(
                allowed=allowed,
                limit=limit,
                remaining=remaining,
                reset_at=reset_at,
                retry_after=retry_after
            )
            
        except Exception as e:
            logger.error(f"Error checking rate limit: {e}", exc_info=True)
            return self._fail_result(limit, window)
    
    async def get_usage(
        self,
        key: str,
        window: Union[LimitWindow, int] = LimitWindow.MINUTE
    ) -> int:
        """
        Get current usage count for a limit key.
        
        Args:
            key: Redis key
            window: Time window — :class:`LimitWindow` enum or raw seconds.
        
        Returns:
            Current usage count
        """
        if not self.redis:
            return 0
        
        try:
            _, window_seconds = _normalise_window(window)
            now = time.time()
            window_start = now - window_seconds
            
            # Remove expired entries
            await self.redis.zremrangebyscore(key, 0, window_start)
            
            # Count current requests
            count = await self.redis.zcard(key)
            return count
            
        except Exception as e:
            logger.error(f"Error getting usage: {e}", exc_info=True)
            return 0
    
    def _build_key(
        self,
        actor_type: str,
        actor_id: str,
        feature: str,
        endpoint_class: str,
        window: LimitWindow
    ) -> str:
        """Build Redis key for rate limit."""
        return f"rate_limit:{actor_type}:{actor_id}:{feature}:{endpoint_class}:{window.value}"

# Global rate limiter instance
_rate_limiter: Optional[RateLimiter] = None

def get_rate_limiter() -> RateLimiter:
    """Get or create the global rate limiter instance."""
    global _rate_limiter
    if _rate_limiter is None:
        _rate_limiter = RateLimiter()
    return _rate_limiter

def set_rate_limiter(limiter: RateLimiter) -> None:
    """Set the global rate limiter instance."""
    global _rate_limiter
    _rate_limiter = limiter