"""Tests for ledger #15/#16 — rate-limit middleware failures:

#15: "/" in default skip paths + startswith matching exempted EVERY url,
     globally bypassing the limiter. Matching is now exact-or-child-scoped.
#16: the dynamic module loader reloads rate_limiter at boot and rebinds
     LimitWindow to a fresh class; import-time bindings elsewhere keep the
     stale one, and class-identity isinstance in _normalise_window raised
     TypeError for every request. Normalisation is now value-based.
"""

# pyright: reportAny=false, reportUnknownMemberType=false, reportUnknownArgumentType=false

import asyncio
import importlib
from enum import Enum
from unittest.mock import MagicMock

import pytest


class TestSkipPathMatching:
    def test_root_entry_matches_only_exact_root(self):
        from swx_core.middleware.rate_limit_middleware import _path_matches

        skips = ["/api/utils/health", "/docs", "/openapi.json", "/"]
        assert _path_matches("/", skips)
        assert not _path_matches("/api/billing/data", skips)

    def test_prefix_survives_child_paths(self):
        from swx_core.middleware.rate_limit_middleware import _path_matches

        assert _path_matches("/docs", ["/docs"])
        assert _path_matches("/docs/recipes", ["/docs"])
        assert _path_matches("/api/utils/health", ["/api/utils/health"])
        assert _path_matches("/api/utils/health/live", ["/api/utils/health"])

    def test_no_suffix_or_prefix_confusion(self):
        from swx_core.middleware.rate_limit_middleware import _path_matches

        assert not _path_matches("/docsadmin", ["/docs"])
        assert not _path_matches("/api/utils/healthcheck", ["/api/utils/health"])
        assert not _path_matches("/openapi.json.bak", ["/openapi.json"])

    def test_default_skip_paths_do_not_neutralize_limiter(self):
        from swx_core.middleware.rate_limit_middleware import (
            RateLimitMiddleware,
            _path_matches,
        )

        mw = RateLimitMiddleware(app=MagicMock())
        assert not _path_matches("/api/user/billing", mw.skip_paths)


class TestWindowNormalization:
    def test_same_class_enum(self):
        from swx_core.services.rate_limit.rate_limiter import (
            LimitWindow,
            _normalise_window,
        )

        assert _normalise_window(LimitWindow.MINUTE) == (LimitWindow.MINUTE, 60)

    def test_foreign_class_enum_matches_by_value(self):
        from swx_core.services.rate_limit.rate_limiter import (
            LimitWindow,
            _normalise_window,
        )

        class ForeignLimitWindow(str, Enum):
            MINUTE = "1m"
            HOUR = "1h"
            DAY = "24h"

        assert ForeignLimitWindow is not LimitWindow
        assert _normalise_window(ForeignLimitWindow.HOUR) == (LimitWindow.HOUR, 3600)

    def test_raw_strings_accepted(self):
        from swx_core.services.rate_limit.rate_limiter import (
            LimitWindow,
            _normalise_window,
        )

        assert _normalise_window("1m") == (LimitWindow.MINUTE, 60)
        assert _normalise_window("24h") == (LimitWindow.DAY, 86400)

    def test_invalid_inputs_raise(self):
        from swx_core.services.rate_limit.rate_limiter import (
            LimitWindow,
            _normalise_window,
        )

        with pytest.raises(ValueError):
            _normalise_window("3h")
        with pytest.raises(ValueError):
            _normalise_window(120)
        with pytest.raises(TypeError):
            _normalise_window(True)
        with pytest.raises(TypeError):
            _normalise_window(LimitWindow)

    def test_survives_module_reload_with_stale_binding(self):
        """The #16 repro: reload rate_limiter, pass a pre-reload enum member."""
        from swx_core.middleware import rate_limit_middleware as mw

        stale_member = mw.LimitWindow.MINUTE

        import swx_core.services.rate_limit.rate_limiter as rl
        importlib.reload(rl)
        assert rl.LimitWindow is not mw.LimitWindow

        class FakePipeline:
            def zremrangebyscore(self, *args):
                return self

            def zcard(self, *args):
                return self

            def zadd(self, *args, **kwargs):
                return self

            def expire(self, *args):
                return self

            async def execute(self):
                return (True, 3, True, True)

        class FakeRedis:
            def pipeline(self):
                return FakePipeline()

        limiter = rl.RateLimiter(FakeRedis())
        result = asyncio.run(limiter.check_limit("k", 100, stale_member))
        assert result.allowed is True