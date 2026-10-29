"""Tests for ledger ISSUE-1/ISSUE-2 from
locang-postcode-gateway/docs/verification/known-swx-core-issues.md:

ISSUE-1: `swx db setup`/`swx db seed` must invoke database modules by
``python -m`` (works from site-packages), not CWD-relative script paths.
ISSUE-2: bcrypt dependency range must stay inside the band passlib 1.7.4
supports (bcrypt >= 4.1 removed ``__about__`` which passlib probes).
"""

# pyright: reportAny=false, reportUnknownMemberType=false, reportUnknownArgumentType=false

from pathlib import Path
from unittest.mock import patch

import pytest
from click.testing import CliRunner


class TestDbCommandInvocation:
    def _run(self, command_name: str, monkeypatch):
        from swx_core.cli.commands.db import db as db_group

        captured = {}
        real_run = __import__("swx_core.cli.commands.db", fromlist=["subprocess"]).subprocess.run

        def fake_run(cmd, **kwargs):
            captured["cmd"] = cmd
            return real_run(["true"], check=False)  # cheap no-op process

        monkeypatch.setattr("swx_core.cli.commands.db.subprocess.run", fake_run)
        result = CliRunner().invoke(db_group, [command_name])
        assert result.exception is None or isinstance(result.exception, SystemExit), result.output
        return captured["cmd"]

    def test_setup_uses_module_invocation(self, monkeypatch):
        cmd = self._run("setup", monkeypatch)
        assert cmd[1:3] == ["-m", "swx_core.database.db_setup"], cmd
        assert cmd[0] != "python"  # interpreter-pinned via sys.executable

    def test_seed_uses_module_invocation(self, monkeypatch):
        cmd = self._run("seed", monkeypatch)
        assert cmd[1:3] == ["-m", "swx_core.database.db_seed"], cmd

    def test_no_cwd_relative_script_path_anywhere(self, monkeypatch):
        for name in ("setup", "seed"):
            cmd = self._run(name, monkeypatch)
            assert all(not str(part).startswith("swx_core/") for part in cmd), cmd


class TestBcryptConstraintBand:
    def test_bcrypt_range_has_upper_bound_below_4_1(self):
        """passlib 1.7.4 probes bcrypt.__about__ (removed in bcrypt >= 4.1)."""
        import tomllib

        content = Path("pyproject.toml").read_text()
        data = tomllib.loads(content)
        bcrypt_deps = [d for d in data["project"]["dependencies"] if d.startswith("bcrypt==") or d.startswith("bcrypt>=")]
        assert bcrypt_deps == ["bcrypt>=4.0.1,<4.1.0"], bcrypt_deps

    def test_passlib_smoke_against_pinned_bcrypt(self):
        """Live hash/verify roundtrip through the declared pair."""
        bcrypt = pytest.importorskip("bcrypt")
        if tuple(int(p) for p in bcrypt.__version__.split(".")[:2]) >= (4, 1):
            pytest.skip(f"local bcrypt {bcrypt.__version__} is outside the supported band")
        from passlib.context import CryptContext

        ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")
        hashed = ctx.hash("correct-horse-battery-staple")
        assert ctx.verify("correct-horse-battery-staple", hashed)
        assert not ctx.verify("wrong", hashed)