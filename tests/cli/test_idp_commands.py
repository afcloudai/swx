# pyright: reportAny=false, reportExplicitAny=false, reportUnknownMemberType=false, reportUnknownArgumentType=false, reportMissingImports=false, reportUnusedCallResult=false

"""
CLI tests for `swx idp` (SWX-IDM-001 D-4): rotate-keys, keys list, seed --demo, bind-admin.
"""

import uuid
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from click.testing import CliRunner

from swx_core.cli.commands.idp import idp

pytestmark = [pytest.mark.unit, pytest.mark.cli]


def _mock_async_session(session: MagicMock) -> MagicMock:
    """A fake ``async_session()`` context factory; __aexit__ returns False so exceptions propagate."""
    return MagicMock(
        return_value=MagicMock(
            __aenter__=AsyncMock(return_value=session),
            __aexit__=AsyncMock(return_value=False),
        )
    )


class TestRotateKeys:
    def test_dry_run_does_not_persist(self) -> None:
        with patch("swx_core.auth.oidc_provider.keys.rotate_signing_keys", new=AsyncMock(return_value={
            "dry_run": True, "algorithm": "RS256", "new_kid": "abc123", "retired_kids": ["old1"],
        })) as rotate:
            result = CliRunner().invoke(idp, ["rotate-keys", "--dry-run"])

        assert result.exit_code == 0, result.output
        rotate.assert_awaited_once_with(
            rotate.call_args.args[0], algorithm="RS256", retirement_days=None, dry_run=True, actor_id="cli:swx-idp",
        )
        assert "dry-run" in result.output and "abc123" in result.output

    def test_rotation_reports_retired(self) -> None:
        with patch(
            "swx_core.auth.oidc_provider.keys.rotate_signing_keys",
            new=AsyncMock(return_value={
                "dry_run": False, "algorithm": "EdDSA", "new_kid": "newkid",
                "retired_kids": ["oldkid"], "retires_at": datetime(2026, 11, 23),
            }),
        ):
            result = CliRunner().invoke(idp, ["rotate-keys", "--algorithm", "EdDSA"])

        assert result.exit_code == 0, result.output
        assert "newkid" in result.output and "oldkid" in result.output


class TestKeysList:
    def test_empty_listing_hints_rotation(self) -> None:
        with patch("swx_core.auth.oidc_provider.repositories.list_publishable_keys", new=AsyncMock(return_value=[])):
            result = CliRunner().invoke(idp, ["keys", "list"])

        assert result.exit_code == 0, result.output
        assert "No signing keys" in result.output

    def test_lists_keys(self) -> None:
        row = MagicMock(kid="kid1", algorithm="RS256", status="active", retires_at=None, created_at=datetime.now())
        with patch("swx_core.auth.oidc_provider.repositories.list_publishable_keys", new=AsyncMock(return_value=[row])):
            result = CliRunner().invoke(idp, ["keys", "list"])

        assert result.exit_code == 0, result.output
        assert "kid1" in result.output and "RS256" in result.output


class TestSeedDemo:
    def test_creates_both_demo_clients_idempotent(self) -> None:
        with (
            patch("swx_core.auth.oidc_provider.repositories.get_client_by_public_id", new=AsyncMock(return_value=None)),
            patch("swx_core.auth.oidc_provider.admin.create_client", new=AsyncMock(return_value=MagicMock())) as create,
        ):
            result = CliRunner().invoke(idp, ["seed", "--demo"])

        assert result.exit_code == 0, result.output
        assert create.await_count == 2
        body = create.call_args_list[0].args[1]
        assert body.client_id == "swx-demo-confidential" and body.client_secret

    def test_skips_existing_clients(self) -> None:
        with (
            patch("swx_core.auth.oidc_provider.repositories.get_client_by_public_id", new=AsyncMock(return_value=MagicMock())),
            patch("swx_core.auth.oidc_provider.admin.create_client", new=AsyncMock()) as create,
        ):
            result = CliRunner().invoke(idp, ["seed", "--demo"])

        assert result.exit_code == 0, result.output
        create.assert_not_awaited()
        assert "exists" in result.output

    def test_requires_demo_flag(self) -> None:
        result = CliRunner().invoke(idp, ["seed"])
        assert result.exit_code != 0


class TestBindAdmin:
    def test_binds_role(self) -> None:
        admin = MagicMock(id=uuid.uuid4(), email="op@example.com")
        role = MagicMock(id=uuid.uuid4(), name="admin")

        session = MagicMock()
        session.execute = AsyncMock(
            side_effect=[
                MagicMock(scalar_one_or_none=MagicMock(return_value=admin)),
                MagicMock(scalar_one_or_none=MagicMock(return_value=role)),
                MagicMock(scalar_one_or_none=MagicMock(return_value=None)),
            ]
        )
        session.commit = AsyncMock()

        with patch("swx_core.database.db.async_session", new=_mock_async_session(session)):
            result = CliRunner().invoke(idp, ["bind-admin", "--admin-email", "op@example.com"])

        assert result.exit_code == 0, result.output
        assert "Bound op@example.com to role admin" in result.output
        session.add.assert_called_once()
        session.commit.assert_awaited_once()

    def test_unknown_admin_fails(self) -> None:
        session = MagicMock()
        session.execute = AsyncMock(side_effect=[MagicMock(scalar_one_or_none=MagicMock(return_value=None))])

        with patch("swx_core.database.db.async_session", new=_mock_async_session(session)):
            result = CliRunner().invoke(idp, ["bind-admin", "--admin-email", "missing@example.com"])

        assert result.exit_code != 0
        assert "not found" in result.output