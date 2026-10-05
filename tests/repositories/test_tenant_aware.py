"""Tests for the tenant-filter silent WHERE-false fix (V2-015):

TenantAwareRepository used to discard a set tenant context when the model
lacked the configured tenant/team field, silently producing WHERE false —
every read returned zero rows with no error. Now it fails fast:
- construction raises ConfigurationError when the model has neither field
- query-time raises when context is set but unbindable
- no-context still means legitimate fail-closed WHERE false
"""

# pyright: reportAny=false, reportUnknownMemberType=false, reportUnknownArgumentType=false

import uuid
from unittest.mock import MagicMock

import pytest
from sqlalchemy import select
from sqlmodel import Field, SQLModel

from swx_core.core.tenant import clear_current_tenant, tenant_context
from swx_core.repositories.tenant_aware import TenantAwareRepository
from swx_core.utils.errors import ConfigurationError


class OrgKeyedModel(SQLModel, table=True):
    """Org-keyed table (the audit's OrganizationMember shape)."""

    __tablename__ = "t_probe_org_keyed"

    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    organization_id: uuid.UUID = Field(default_factory=uuid.uuid4)


class TenantKeyedModel(SQLModel, table=True):
    __tablename__ = "t_probe_tenant_keyed"

    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    tenant_id: uuid.UUID = Field(default_factory=uuid.uuid4)


class TeamOnlyModel(SQLModel, table=True):
    __tablename__ = "t_probe_team_only"

    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    team_id: uuid.UUID = Field(default_factory=uuid.uuid4)


explicit_tenant_id = str(uuid.uuid4())
distracting_tenant_id = uuid.uuid4()


class TestTenantAwareRepositoryWiring:
    def setup_method(self):
        clear_current_tenant()

    def teardown_method(self):
        clear_current_tenant()

    def test_default_wiring_rejects_org_keyed_model(self):
        with pytest.raises(ConfigurationError, match="organization_id"):
            TenantAwareRepository(model=OrgKeyedModel)

    def test_org_keyed_wiring_constructs(self):
        repo = TenantAwareRepository(model=OrgKeyedModel, tenant_field="organization_id")
        assert repo.tenant_field == "organization_id"

    def test_framework_organization_member_default_wiring_rejected(self):
        from swx_core.models.organization import OrganizationMember

        with pytest.raises(ConfigurationError):
            TenantAwareRepository(model=OrganizationMember)

    def test_framework_organization_member_org_wiring_accepted(self):
        from swx_core.models.organization import OrganizationMember

        TenantAwareRepository(model=OrganizationMember, tenant_field="organization_id")

    def test_tenant_keyed_model_default_wiring_accepted(self):
        TenantAwareRepository(model=TenantKeyedModel)


class TestTenantFilterSemantics:
    def setup_method(self):
        clear_current_tenant()

    def teardown_method(self):
        clear_current_tenant()

    def test_set_context_binds_tenant_field(self):
        tenant_id = uuid.uuid4()
        with tenant_context(tenant_id):
            query = TenantAwareRepository(model=TenantKeyedModel)._apply_tenant_filter(
                select(TenantKeyedModel)
            )
        assert "tenant_id" in str(query.compile())
        assert "false" not in str(query.compile()).lower()

    def test_set_context_unbindable_raises(self):
        with tenant_context(uuid.uuid4()):
            with pytest.raises(ConfigurationError, match="cannot bind"):
                TenantAwareRepository(model=TeamOnlyModel)._apply_tenant_filter(
                    select(TeamOnlyModel)
                )

    def test_no_context_fails_closed_to_where_false(self):
        query = TenantAwareRepository(model=TeamOnlyModel)._apply_tenant_filter(
            select(TeamOnlyModel)
        )
        assert "false" in str(query.compile()).lower()

    def test_team_context_binds_team_field(self):
        team_id = uuid.uuid4()
        query = TenantAwareRepository(model=TeamOnlyModel, team_field="team_id")
        with tenant_context(None, team_id):
            filtered = query._apply_tenant_filter(select(TeamOnlyModel))
        assert "team_id" in str(filtered.compile())

    def test_super_admin_bypasses_filter(self):
        from swx_core.core.tenant import set_super_admin

        set_super_admin(True)
        try:
            query = TenantAwareRepository(model=TenantKeyedModel)._apply_tenant_filter(
                select(TenantKeyedModel)
            )
        finally:
            set_super_admin(False)
        assert "false" not in str(query.compile()).lower()

    def test_explicit_tenant_id_beats_context(self):
        repo = TenantAwareRepository(
            model=TenantKeyedModel, explicit_tenant_id=explicit_tenant_id
        )
        with tenant_context(distracting_tenant_id):
            assert repo._get_tenant_id() == explicit_tenant_id
            filtered = repo._apply_tenant_filter(select(TenantKeyedModel))
        assert "tenant_id" in str(filtered.compile())