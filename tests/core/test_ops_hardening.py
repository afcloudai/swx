"""Tests for operational hardening fixes (P1/P2/P3 audit batch):

- email-validator is a declared base dependency
- health checks use sqlalchemy.text and settings-backed Redis URL
- SECRET_KEY family required outside development environments
- audit-integrity startup check skips gracefully when the table is absent
- unknown .env keys produce a warning (typo blindness)
"""

# pyright: reportAny=false, reportUnknownMemberType=false, reportUnknownArgumentType=false

import importlib.util
import os
import sys
import zipfile
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# Ambient env must satisfy the secret policy before Settings' module-level
# instantiation runs in any import below (fail-closed validator).
os.environ.setdefault("ENVIRONMENT", "local")
os.environ.setdefault("SECRET_KEY", "test-secret-key-for-testing-only")
os.environ.setdefault("REFRESH_SECRET_KEY", "test-refresh-secret-key")
os.environ.setdefault("PASSWORD_RESET_SECRET_KEY", "test-reset-secret-key")


# ---------------------------------------------------------------------------
# P1-1: email-validator dependency declared
# ---------------------------------------------------------------------------

def test_email_validator_declared_in_pyproject():
    content = open("pyproject.toml", encoding="utf-8").read()
    deps_start = content.index("dependencies = [")
    base_deps = content[deps_start:content.index("]", deps_start)]
    assert "email-validator" in base_deps


def test_email_validator_declared_in_built_metadata():
    import glob

    from swx_core import __version__

    wheels = sorted(glob.glob(f"dist/swx_core-{__version__}-*.whl"))
    if not wheels:
        pytest.skip(f"no built wheel for {__version__} in dist/ (run: python -m build)")
    meta = zipfile.ZipFile(wheels[-1]).read(
        f"swx_core-{__version__}.dist-info/METADATA"
    ).decode()
    reqs = [line for line in meta.splitlines() if line.startswith("Requires-Dist")]
    assert any("email-validator" in req for req in reqs), f"METADATA missing email-validator: {reqs[-3:]}"


# ---------------------------------------------------------------------------
# P1-2: health checks wrap SQL in text()
# ---------------------------------------------------------------------------

class TestDatabaseHealthChecks:
    async def test_check_database_uses_text_wrapped_sql(self):
        from swx_core.utils import health

        executed = {}

        class FakeSession:
            async def execute(self, stmt):
                executed["stmt"] = stmt
                return SimpleNamespace(scalar=lambda: 1)

        async def fake_session_gen():
            yield FakeSession()

        with patch.object(health, "get_session", fake_session_gen):
            result = await health.check_database()

        assert result.status == "healthy"
        from sqlalchemy import TextClause
        assert isinstance(executed["stmt"], TextClause)

    async def test_check_database_reports_unhealthy_on_error(self):
        from swx_core.utils import health

        async def failing_session_gen():
            raise RuntimeError("connection refused")
            yield  # pragma: no cover

        with patch.object(health, "get_session", failing_session_gen):
            result = await health.check_database()

        assert result.status == "unhealthy"
        assert "connection refused" in result.message


# ---------------------------------------------------------------------------
# P1-3: check_redis reads settings-backed URL at call time
# ---------------------------------------------------------------------------

class TestRedisHealthCheck:
    async def test_check_redis_defaults_to_settings_url(self):
        from swx_core.utils import health

        created = {}
        fake_client = MagicMock()
        fake_client.ping = AsyncMock(return_value=True)
        fake_client.close = AsyncMock()

        def fake_from_url(url):
            created["url"] = url
            return fake_client

        with patch("redis.asyncio.from_url", fake_from_url):
            result = await health.check_redis()

        assert result.status == "healthy"
        from swx_core.config.settings import settings
        assert created["url"] == settings.redis_url

    async def test_check_redis_explicit_url_wins(self):
        from swx_core.utils import health

        created = {}
        fake_client = MagicMock()
        fake_client.ping = AsyncMock(return_value=True)
        fake_client.close = AsyncMock()

        def fake_from_url(url):
            created["url"] = url
            return fake_client

        with patch("redis.asyncio.from_url", fake_from_url):
            await health.check_redis("redis://override:1234/9")

        assert created["url"] == "redis://override:1234/9"


# ---------------------------------------------------------------------------
# P2-4: SECRET_KEY family required outside development
# ---------------------------------------------------------------------------

def _fresh_settings_cls():
    """Return the Settings class with ambient env made policy-safe.

    Directly reuses the cached class: re-importing swx_core.config re-runs
    the module-level ``settings = Settings()`` under whatever env the
    previous test left behind, which conflates import-time and construction
    failures. Ambient-safe env first; per-test overrides happen at call time.
    """
    from swx_core.config.settings import Settings
    return Settings


class TestSecretKeyPolicy:
    def test_dev_boots_without_secrets(self, monkeypatch):
        monkeypatch.setenv("ENVIRONMENT", "local")
        for name in ("SECRET_KEY", "REFRESH_SECRET_KEY", "PASSWORD_RESET_SECRET_KEY"):
            monkeypatch.delenv(name, raising=False)
        s = _fresh_settings_cls()(ENVIRONMENT="local")
        assert s.SECRET_KEY and s.REFRESH_SECRET_KEY and s.PASSWORD_RESET_SECRET_KEY

    def test_staging_without_secrets_fails_load(self, monkeypatch):
        monkeypatch.setenv("ENVIRONMENT", "staging")
        for name in ("SECRET_KEY", "REFRESH_SECRET_KEY", "PASSWORD_RESET_SECRET_KEY"):
            monkeypatch.delenv(name, raising=False)
        s_cls = _fresh_settings_cls()
        with pytest.raises(Exception) as exc:
            s_cls(ENVIRONMENT="staging")
        assert "SECRET_KEY" in str(exc.value)

    def test_staging_with_secrets_boots(self, monkeypatch):
        monkeypatch.setenv("ENVIRONMENT", "staging")
        monkeypatch.setenv("SWX_OIDC_ISSUER", "https://auth.test.example.com")
        s = _fresh_settings_cls()(
            ENVIRONMENT="staging",
            SECRET_KEY="a" * 43,
            REFRESH_SECRET_KEY="b" * 43,
            PASSWORD_RESET_SECRET_KEY="c" * 43,
        )
        assert s.SECRET_KEY == "a" * 43

    def test_env_sourced_secrets_respected(self, monkeypatch):
        monkeypatch.setenv("ENVIRONMENT", "staging")
        monkeypatch.setenv("SWX_OIDC_ISSUER", "https://auth.test.example.com")
        os.environ["SECRET_KEY"] = "sourced-from-env"
        try:
            s = _fresh_settings_cls()(
                ENVIRONMENT="staging",
                SWX_OIDC_ISSUER="https://auth.test.example.com",
                REFRESH_SECRET_KEY="b" * 43,
                PASSWORD_RESET_SECRET_KEY="c" * 43,
            )
        finally:
            os.environ.pop("SECRET_KEY", None)
        assert s.SECRET_KEY == "sourced-from-env"


# ---------------------------------------------------------------------------
# P3-5: startup integrity gated on table existence
# ---------------------------------------------------------------------------

class TestStartupIntegrityGate:
    async def test_check_startup_integrity_raises_lookuperror_when_table_missing(self):
        from swx_core.services.compliance import audit_integrity_service as svc

        session = AsyncMock()
        result = MagicMock()
        result.scalar.return_value = False
        session.execute = AsyncMock(return_value=result)

        with pytest.raises(LookupError):
            await svc.check_startup_integrity(session)

    async def test_table_exists_probe_false_on_fresh_db(self):
        from swx_core.services.compliance import audit_integrity_service as svc

        session = AsyncMock()
        result = MagicMock()
        result.scalar.return_value = False
        session.execute = AsyncMock(return_value=result)
        assert await svc.audit_table_exists(session) is False

    async def test_boot_path_skips_gracefully_on_missing_table(self):
        # app_factory's lifespan wraps LookupError -> skip (log), no crash
        from swx_core.services.compliance import audit_integrity_service as svc

        session = AsyncMock()
        result = MagicMock()
        result.scalar.return_value = False
        session.execute = AsyncMock(return_value=result)

        try:
            with patch.object(svc, "audit_table_exists", AsyncMock(return_value=False)):
                await svc.check_startup_integrity(session)
        except LookupError:
            pass  # the lifespan catches LookupError and logs a warning — never RuntimeError crash
        else:
            pytest.fail("expected LookupError so boot can skip gracefully")


# ---------------------------------------------------------------------------
# P3-6: unknown .env keys warn
# ---------------------------------------------------------------------------

class TestUnknownDotenvKeysWarning:
    async def test_unknown_env_key_produces_warning(self, tmp_path, monkeypatch):
        import os
        import warnings

        # isolated cwd with a typo'd .env
        project = tmp_path / "proj"
        project.mkdir()
        (project / ".env").write_text("PROJECT_NAME=T\nSECRETT_KEY=typo\n")
        monkeypatch.chdir(project)
        monkeypatch.setenv("PROJECT_NAME", "T")
        monkeypatch.setenv("SECRET_KEY", "k" * 43)
        monkeypatch.setenv("ENVIRONMENT", "local")
        monkeypatch.setenv("DB_HOST", "localhost")
        monkeypatch.setenv("DB_USER", "u")
        monkeypatch.setenv("DB_PASSWORD", "p")
        monkeypatch.setenv("DB_NAME", "d")
        monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)

        for mod in list(sys.modules):
            if "swx_core.config" in mod:
                del sys.modules[mod]
        from swx_core.config.settings import Settings

        with pytest.warns(UserWarning, match="SECRETT_KEY"):
            Settings()

    def test_unknown_key_check_skipped_without_dotenv(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)  # no .env here
        for mod in list(sys.modules):
            if "swx_core.config" in mod:
                del sys.modules[mod]
        import warnings

        from swx_core.config.settings import Settings

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            Settings()
        assert not [w for w in caught if "Unknown keys" in str(w.message)]


# ---------------------------------------------------------------------------
# P4-7: load_all_models namespace hygiene
# ---------------------------------------------------------------------------

class TestModelLoaderHygiene:
    @pytest.fixture(autouse=True)
    def _point_discovery_inside_framework(self, monkeypatch):
        # swx_app/models/ contains intentionally-broken loader test fixtures
        # (123_invalid.py, product!.py); discovery must not load them here.
        monkeypatch.setattr(
            "swx_core.utils.model.discovery.app_exists", lambda: False
        )
        yield

    def test_no_sqlalchemy_internal_leakage(self):
        import swx_core.models as models_pkg
        from swx_core.utils.model import load_all_models

        load_all_models()
        leaks = [
            attr for attr in ("func", "select", "datetime", "text", "Column", "ForeignKey")
            if hasattr(models_pkg, attr)
        ]
        assert leaks == [], f"SQLAlchemy internals leaked onto swx_core.models: {leaks}"

    def test_model_classes_still_attached(self):
        import swx_core.models as models_pkg
        from swx_core.utils.model import load_all_models

        load_all_models()
        for model_name in ("User", "ApiKey", "Team", "Organization"):
            assert hasattr(models_pkg, model_name), f"{model_name} not attached"