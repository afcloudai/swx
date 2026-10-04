"""PostgreSQL Row-Level Security Integration
-----------------------------------------
Sets PostgreSQL session variables for RLS-based tenant isolation.

Security notes
--------------
- Tenant IDs are validated as UUIDs before any SQL is assembled; invalid
  values fail closed (the connection runs without tenant context, which
  RLS policies treat as "no rows visible" via ``current_setting(..., true)``
  + null-tenant policies).
- PostgreSQL does not accept bind parameters for ``SET``/``SET LOCAL``.
  The parameterized equivalent is ``SELECT set_config(:key, :value, :is_local)``
  and is used wherever we hold a SQLAlchemy connection.
- The pool-checkout listener only has a raw DBAPI connection (no bind
  protocol there), so it assembles ``set_config(...)`` SQL from a fixed
  key constant + canonical-UUID/boolean values — injection-proof by
  construction, and a checkin listener RESETs the variables so pooled
  connections never carry stale tenant context.

Usage::

    from swx_core.database.rls import setup_rls_event_listeners

    setup_rls_event_listeners(engine)  # per-checkout tenant context

Policy templates: see :func:`tenant_rls_policy_sql` and
``database/migrations/rls_template.sql``.
"""

import uuid

from sqlalchemy import event, text
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import AsyncEngine

from swx_core.core.tenant import get_current_tenant_id, is_super_admin

_TENANT_KEY = "app.current_tenant_id"
_SUPER_ADMIN_KEY = "app.is_super_admin"

_SET_CONFIG_SQL = text("SELECT set_config(:key, :value, :is_local)")


def _validated_tenant_uuid(tenant_id) -> uuid.UUID | None:
    """Return tenant_id as a UUID, or None if unset/invalid.

    Invalid values must fail closed (no tenant context) rather than reach
    SQL assembly.
    """
    if tenant_id is None:
        return None
    if isinstance(tenant_id, uuid.UUID):
        return tenant_id
    try:
        return uuid.UUID(str(tenant_id))
    except (ValueError, TypeError):
        return None


def set_tenant_context_on_connection(dbapi_conn, tenant_id, is_super_admin_flag: bool) -> None:
    """Set tenant context on a raw DBAPI connection (checkout-listener path).

    Values are canonicalized before assembly: keys are module constants,
    tenant_id is a validated UUID and the flag is a Python bool formatted
    to lowercase. No caller-controlled string reaches the SQL verbatim.
    """
    tenant_uuid = _validated_tenant_uuid(tenant_id)

    cursor = dbapi_conn.cursor()
    try:
        if tenant_uuid is not None:
            cursor.execute(
                f"SELECT set_config('{_TENANT_KEY}', '{tenant_uuid}', false)"
            )
        cursor.execute(
            f"SELECT set_config('{_SUPER_ADMIN_KEY}', '{str(bool(is_super_admin_flag)).lower()}', false)"
        )
    finally:
        cursor.close()


def setup_rls_event_listeners(engine: AsyncEngine) -> None:
    """Attach per-checkout/per-checkin listeners for tenant context.

    Uses session-scoped ``set_config`` at checkout and RESETs at checkin,
    so pooled connections never leak tenant context between requests.
    (The previous ``connect``-event + ``SET LOCAL`` variant was a no-op:
    it ran outside any transaction.)
    """

    @event.listens_for(engine.sync_engine, "checkout")
    def set_tenant_rls_context(dbapi_conn, connection_record):
        set_tenant_context_on_connection(
            dbapi_conn, get_current_tenant_id(), is_super_admin()
        )

    @event.listens_for(engine.sync_engine, "checkin")
    def reset_tenant_rls_context(dbapi_conn, connection_record):
        cursor = dbapi_conn.cursor()
        try:
            for key in (_TENANT_KEY, _SUPER_ADMIN_KEY):
                cursor.execute(f"SELECT set_config('{key}', '', false)")
        finally:
            cursor.close()


def setup_rls_for_session(
    connection: Connection,
    tenant_id=None,
    is_super_admin: bool = False,
) -> None:
    """Set tenant context on a SQLAlchemy connection using bind parameters.

    Call this at the start of a transaction::

        async with session.begin():
            await session.exec_driver_sql(...)  # or pass session.connection()

    Args:
        connection: SQLAlchemy (sync-style) Connection — obtain from an
            AsyncSession via ``session.connection()``.
        tenant_id: Tenant UUID (or string coercible to UUID). Invalid
            values are skipped, leaving the connection without tenant
            context (fail-closed under RLS policies).
        is_super_admin: Whether this connection bypasses tenant filtering.
    """
    tenant_uuid = _validated_tenant_uuid(tenant_id)
    if tenant_uuid is not None:
        connection.execute(
            _SET_CONFIG_SQL,
            {"key": _TENANT_KEY, "value": str(tenant_uuid), "is_local": "false"},
        )
    connection.execute(
        _SET_CONFIG_SQL,
        {"key": _SUPER_ADMIN_KEY, "value": str(bool(is_super_admin)).lower(), "is_local": "false"},
    )


def tenant_rls_policy_sql(table: str, tenant_column: str = "tenant_id") -> str:
    """Generate an RLS enable + tenant-isolation policy pair for a table.

    Identifiers are validated against Postgres's lowercase identifier
    rules before being embedded into the DDL string.

    Returns:
        SQL text enabling RLS and adding a tenant-isolation policy.
    """
    if not (_is_pg_identifier(table) and _is_pg_identifier(tenant_column)):
        raise ValueError("table and tenant_column must be lowercase SQL identifiers")

    return (
        f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY;\n"
        f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY;\n"
        f"CREATE POLICY {table}_tenant_isolation ON {table} "
        f"USING ({tenant_column} = current_setting('{_TENANT_KEY}', true)::uuid) "
        f"WITH CHECK ({tenant_column} = current_setting('{_TENANT_KEY}', true)::uuid);"
    )


def _is_pg_identifier(name: str) -> bool:
    """True when name is a safe lowercase Postgres identifier."""
    if not name or len(name) > 63:
        return False
    return all(ch.islower() or ch.isdigit() or ch == "_" for ch in name) and name[0].isalpha()