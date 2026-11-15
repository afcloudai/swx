# pyright: reportAny=false, reportExplicitAny=false, reportUnknownMemberType=false, reportUnknownArgumentType=false, reportMissingImports=false, reportUnusedCallResult=false, reportAttributeAccessIssue=false, reportArgumentType=false, reportCallIssue=false

"""
Regression tests for the framework reality-check fixes:
- BaseRepository.exists_by missing-self (instance calls raised TypeError)
- TenantAwareController split-brain (injected services bypassed tenant filtering)
- TenantAwareController.list totals counted only the current page
- Payment-provider inbound webhooks mounted at app factory
"""

import inspect
import pathlib
import uuid
from unittest.mock import AsyncMock, MagicMock

import pytest
from sqlmodel import Field, SQLModel

from swx_core.bootstrap import register_webhook_routes
from swx_core.controllers.tenant_aware import TenantAwareController
from swx_core.repositories.base import BaseRepository

pytestmark = pytest.mark.unit


class _FakeModel(SQLModel, table=True):
    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    tenant_id: uuid.UUID | None = Field(default=None)
    team_id: uuid.UUID | None = Field(default=None)


def _repo_with_session() -> BaseRepository:
    repo = BaseRepository(_FakeModel)
    fake_session = MagicMock()
    result = MagicMock()
    result.scalar.return_value = 5
    fake_session.execute = AsyncMock(return_value=result)
    repo.session = fake_session
    return repo


class TestExistsByRegression:
    def test_signature_carries_self(self) -> None:
        params = list(inspect.signature(BaseRepository.exists_by).parameters)
        assert params[0] == "self"

    async def test_instance_call_no_longer_raises(self) -> None:
        """Pre-fix: repo.exists_by(x=1) raised TypeError (missing self)."""
        repo = _repo_with_session()
        result = await repo.exists_by(x=1)
        _ = result  # executed means the signature fixed it

    async def test_counts_matching_rows(self) -> None:
        repo = _repo_with_session()
        found = await repo.exists_by(email="ayo@example.com")

        assert found is True


class _StubPublic:
    pass


class _StubService:
    def __init__(self) -> None:
        self.repository = "non-tenant-repo"


class TestTenantAwareControllerRegression:
    def _controller(self, service: object | None) -> TenantAwareController:
        return TenantAwareController(model=_FakeModel, schema_public=_StubPublic, service=service)

    def test_injected_service_gains_tenant_repository(self) -> None:
        """Pre-fix: an injected service kept its non-tenant repository (split-brain)."""
        service = _StubService()
        controller = self._controller(service=service)

        assert controller.service is service
        assert service.repository is controller.repository

    def test_default_service_uses_tenant_repository(self) -> None:
        controller = self._controller(service=None)

        assert controller.service.repository is controller.repository

    async def test_list_total_uses_repository_count(self) -> None:
        controller = self._controller(service=None)
        controller.repository.find_all = AsyncMock(return_value=[])
        controller.repository.count = AsyncMock(return_value=42)

        page = await controller.list(skip=20, limit=20)

        assert page.total == 42
        assert page.data == []
        assert len(controller.repository.count.await_args.args) == 0


class TestWebhookMounting:
    def test_registers_all_payment_provider_webhooks(self) -> None:
        app = MagicMock()
        register_webhook_routes(app)

        assert app.include_router.call_count == 3


class TestAppFactoryWiring:
    def test_app_factory_calls_register_webhook_routes(self) -> None:
        import inspect

        from swx_core.app_factory import create_swx_app

        source = inspect.getsource(create_swx_app)
        assert "register_webhook_routes" in source


class TestAlembicIniFinding:
    def test_root_ini_wires_framework_chain(self) -> None:
        """Fixed: root alembic.ini exists and points at the framework chain."""
        import configparser

        ini = pathlib.Path.cwd() / "alembic.ini"
        assert ini.exists()
        cp = configparser.ConfigParser()
        cp.read(ini)
        assert cp["alembic"]["script_location"] == "swx_core/template/project/migrations"
