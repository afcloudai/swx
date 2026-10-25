"""IdP CLI Commands (SWX-IDM-001)
---------------------------------
Operator commands for the OIDC identity provider.

- ``swx idp rotate-keys``      — rotate signing keys (new active kid; previous
  keys fall to verify-only until ``SWX_OIDC_KEY_RETIREMENT_DAYS`` elapses)
- ``swx idp keys list``        — list signing keys and their lifecycle state
- ``swx idp seed --demo``      — seed one confidential + one public first-party
  demo client (idempotent on the demo client_ids)
- ``swx idp bind-admin``       — grant an admin identity an RBAC role binding
  (bootstraps ``idp:clients:*`` for non-root operators; idempotent)
"""

from __future__ import annotations

import asyncio

import click

_DEMO_CONFIDENTIAL_CLIENT_ID = "swx-demo-confidential"
_DEMO_PUBLIC_CLIENT_ID = "swx-demo-public"


async def _rotate(algorithm: str, retirement_days: int | None, dry_run: bool) -> dict[str, object]:
    from swx_core.auth.oidc_provider.keys import rotate_signing_keys
    from swx_core.database.db import async_session

    async with async_session() as session:
        return await rotate_signing_keys(
            session, algorithm=algorithm, retirement_days=retirement_days, dry_run=dry_run, actor_id="cli:swx-idp"
        )


async def _list_keys() -> list[dict[str, object]]:
    from swx_core.auth.oidc_provider import repositories
    from swx_core.database.db import async_session
    from swx_core.utils.time import utc_now

    async with async_session() as session:
        rows = await repositories.list_publishable_keys(session, utc_now())
        return [
            {
                "kid": key.kid,
                "algorithm": key.algorithm,
                "status": key.status,
                "retires_at": key.retires_at,
                "created_at": key.created_at,
            }
            for key in rows
        ]


async def _seed_demo() -> dict[str, str]:
    from swx_core.auth.oidc_provider import admin as oidc_admin
    from swx_core.auth.oidc_provider import repositories
    from swx_core.auth.oidc_provider.models import OIDCClientCreate
    from swx_core.database.db import async_session

    specs = [
        (
            _DEMO_CONFIDENTIAL_CLIENT_ID,
            "Demo Confidential Client (server products)",
            OIDCClientCreate(
                name="Demo Confidential Client (server products)",
                client_id=_DEMO_CONFIDENTIAL_CLIENT_ID,
                client_secret="demo-confidential-secret",
                grant_types=["authorization_code", "refresh_token", "client_credentials"],
                redirect_uris=["https://demo.example.com/callback"],
                is_first_party=True,
                is_trusted=True,
            ),
        ),
        (
            _DEMO_PUBLIC_CLIENT_ID,
            "Demo Public Client (SPAs / mobile)",
            OIDCClientCreate(
                name="Demo Public Client (SPAs / mobile)",
                client_id=_DEMO_PUBLIC_CLIENT_ID,
                grant_types=["authorization_code", "refresh_token"],
                redirect_uris=["https://demo.example.com/callback"],
                is_first_party=True,
                is_trusted=True,
            ),
        ),
    ]
    result: dict[str, str] = {}
    async with async_session() as session:
        for client_id, _, spec in specs:
            if await repositories.get_client_by_public_id(session, client_id) is not None:
                result[client_id] = "exists"
                continue
            await oidc_admin.create_client(session, spec, actor_id="cli:swx-idp-seed")
            result[client_id] = "created"
    return result


@click.group()
def idp():
    """OIDC identity provider operations (SWX-IDM-001)."""


@idp.command("rotate-keys")
@click.option("--algorithm", type=click.Choice(["RS256", "EdDSA"]), default="RS256", show_default=True)
@click.option(
    "--retirement-days",
    type=int,
    default=None,
    help="Verify-only window in days (default: SWX_OIDC_KEY_RETIREMENT_DAYS)",
)
@click.option("--dry-run", is_flag=True, default=False, help="Preview the rotation without persisting.")
def rotate_keys(algorithm: str, retirement_days: int | None, dry_run: bool) -> None:
    """Rotate signing keys; previous active key stays verify-only until retirement."""
    result = asyncio.run(_rotate(algorithm, retirement_days, dry_run))
    if result.get("dry_run"):
        click.secho(f"[dry-run] would activate kid {result['new_kid']} ({algorithm})", fg="yellow")
        retired = result.get("retired_kids") or []
        click.echo(f"would demote to verify-only: {', '.join(map(str, retired)) or 'none'}")
    else:
        click.secho(f"Activated kid {result['new_kid']} ({algorithm}).", fg="green")
        retired = result.get("retired_kids") or []
        click.echo(f"verify-only until {result['retires_at']}: {', '.join(map(str, retired)) or 'none'}")


@idp.group()
def keys():
    """Signing-key operations."""


@keys.command("list")
def keys_list() -> None:
    """List signing keys (active and verify-only) visible in JWKS."""
    rows = asyncio.run(_list_keys())
    if not rows:
        click.secho("No signing keys. Run `swx idp rotate-keys` to create one.", fg="yellow")
        return
    for row in rows:
        retire = str(row["retires_at"]) if row["retires_at"] else "—"
        click.echo(f"{row['kid']}  {row['algorithm']}  {row['status']}  retires: {retire}")


@idp.command("seed")
@click.option("--demo", is_flag=True, default=False, help="Create one confidential + one public first-party demo client.")
def seed(demo: bool) -> None:
    """Seed demo OIDC clients (idempotent)."""
    if not demo:
        raise click.UsageError("Only --demo seeding is supported in v2.30.")
    created = asyncio.run(_seed_demo())
    for client_id, state in created.items():
        click.secho(f"{client_id}: {state}", fg="green" if state == "created" else "yellow")


@idp.command("bind-admin")
@click.option("--admin-email", required=True, help="Admin identity to bind.")
@click.option("--role", "role_name", default="admin", show_default=True, help="Role name to bind.")
def bind_admin(admin_email: str, role_name: str) -> None:
    """Grant an admin identity an RBAC role binding (e.g. for idp:clients:*)."""
    asyncio.run(_bind_admin(admin_email, role_name))


async def _bind_admin(admin_email: str, role_name: str) -> None:
    from sqlalchemy import select

    from swx_core.database.db import async_session
    from swx_core.models.admin_user import AdminUser
    from swx_core.models.admin_user_role import AdminUserRole
    from swx_core.models.role import Role

    async with async_session() as session:
        admin = (
            await session.execute(select(AdminUser).where(AdminUser.email == admin_email))
        ).scalar_one_or_none()
        if admin is None:
            raise click.ClickException(f"Admin identity not found: {admin_email}")
        role = (await session.execute(select(Role).where(Role.name == role_name))).scalar_one_or_none()
        if role is None:
            raise click.ClickException(f"Role not found: {role_name!r}. Run scripts/seed_system.py first.")

        existing = (
            await session.execute(
                select(AdminUserRole).where(
                    AdminUserRole.admin_user_id == admin.id,
                    AdminUserRole.role_id == role.id,
                )
            )
        ).scalar_one_or_none()
        if existing is not None:
            click.secho(f"{admin_email} already bound to {role_name}.", fg="yellow")
            return

        session.add(AdminUserRole(admin_user_id=admin.id, role_id=role.id))
        await session.commit()
        click.secho(f"Bound {admin_email} to role {role_name}.", fg="green")