# Identity Provider (OIDC)

**Version:** 1.0.0
**Last Updated:** 2026-10-24

---

## Table of Contents

1. [Overview](#overview)
2. [Configuration](#configuration)
3. [Database Models](#database-models)
4. [Admin API](#admin-api)
5. [Issuer Endpoints](#issuer-endpoints)
6. [Flows](#flows)
7. [Token Lifecycle](#token-lifecycle)
8. [Key Management](#key-management)
9. [Claims](#claims)
10. [Phone Verification](#phone-verification)
11. [Identity Linking](#identity-linking)
12. [CLI](#cli)
13. [Hardening](#hardening)
14. [Migrations](#migrations)
15. [Testing](#testing)

---

## Overview

SwX-API ships a first-class **OpenID Connect identity provider** (SWX-IDM-001): the framework itself is the
source of truth for ecosystem identity (OAuth 2.1 semantics — authorization-code + PKCE mandatory, no implicit
flow, no ROPC). Person-level identity is **phone-based** (verified phone = the cross-product match key; email is
never required or exposed through IdP claims).

- **Issuer endpoints** — `/oidc/authorize`, `/oidc/token`, `/oidc/revoke` (RFC 7009), `/oidc/userinfo`,
  `/.well-known/openid-configuration`, `/jwks.json`
- **Asymmetric signing** — RS256 (default) / EdDSA with `kid` headers and rotation tooling; HS256 is never used
- **Refresh rotation with reuse detection** — a reused rotated token revokes the whole token family
- **Fail-closed, audited** — every refusal (unknown client, unregistered redirect, PKCE downgrade, code replay,
  scope escalation, client impersonation) is refused and written to the hash-chained audit log
- **Additive-only** — platform JWT/refresh/billing flows are untouched; the only core edit widens `audience`
  to accept plain strings (`oidc_client:<client_id>`)

## Configuration

| Setting | Default | Purpose |
|---|---|---|
| `SWX_OIDC_ISSUER` | *(derived; required outside development)* | Absolute issuer URL. **Production must pin it** — a request-derived issuer is Host-header-poisonable (fail settings load otherwise) |
| `SWX_OIDC_LOGIN_URL` | `/auth/cookie/login` | Where `/oidc/authorize` sends unauthenticated users; the IdP app UI mounts here and redirects back |
| `SWX_OIDC_CODE_TTL_SECONDS` | `60` | Authorization-code lifetime (single use) |
| `SWX_OIDC_ID_TOKEN_TTL_SECONDS` | `3600` | `id_token` lifetime |
| `SWX_OIDC_ACCESS_TTL_SECONDS` | `3600` | OIDC access-token lifetime |
| `SWX_OIDC_REFRESH_TTL_SECONDS` | `1209600` | OIDC refresh-token lifetime |
| `SWX_OIDC_KEY_RETIREMENT_DAYS` | `30` | Days a demoted key stays verify-only |
| `SWX_OIDC_DEFAULT_SIGNING_ALGORITHM` | `RS256` | `RS256` or `EdDSA` |
| `SWX_PHONE_VERIFICATION_CHANNEL` | *(none)* | Registered `PhoneVerificationChannel` name; default logs the code |

The private keys, client secrets and encrypted fields ride the standard `SWX_ENCRYPTION_KEY` /
`SWX_ENCRYPTION_KEY_PREVIOUS` EncryptionService configuration.

## Database Models

| Table | Purpose |
|---|---|
| `swx_oidc_clients` | Registered clients: exact `redirect_uris` list, `grant_types`, `scopes`, per-client TTLs, `is_first_party`, `is_trusted` (skips consent screen — row still recorded), bcrypt `client_secret_hash` (null ⇒ public client) |
| `swx_oidc_grant_codes` | Single-use authorization codes (**SHA-256 hash only**), PKCE challenge, `nonce`, `auth_time`, `acr`, `amr`, 60 s expiry |
| `swx_oidc_consents` | User × client scope consents (unique per pair; re-consent widens, revoke shrinks) |
| `swx_oidc_refresh_tokens` | Rotation families: `family_id` + SHA-256 `token_hash`, status `active`/`rotated`/`revoked` |
| `swx_oidc_signing_keys` | `kid`, algorithm, **encrypted** private PEM, `public_jwk`, status `active`/`verify_only`, `retires_at` |
| `swx_users` (+v2.30.3) | `phone` (E.164, indexed) + `phone_verified_at` |
| `swx_social_accounts` (+v2.30.1 unique index) | External links `(provider, provider_id)` ↔ user — one external subject ↔ one user |
| `swx_admin_user_roles` (+v2.30.2) | Admin↔role bindings enabling strict admin-surface RBAC (`idp:clients:*`) |

## Admin API

All routes under `/api/admin/oidc/clients` (`Admin - OIDC` tag), guarded by `AdminUserDep` **and** the strict
`idp:clients:read|write|manage` permission (resolved over `swx_admin_user_roles`; the `FIRST_SUPERUSER`
platform root is the bootstrap carve-out).

| Method | Path | Permission | Notes |
|---|---|---|---|
| `GET` | `/admin/oidc/clients` | `idp:clients:read` | List (pagination) |
| `POST` | `/admin/oidc/clients` | `idp:clients:write` | Create — hash on write, never returned |
| `GET` | `/admin/oidc/clients/{id}` | `idp:clients:read` | Fetch |
| `PUT` | `/admin/oidc/clients/{id}` | `idp:clients:write` | Update (secret rotation supported) |
| `DELETE` | `/admin/oidc/clients/{id}` | `idp:clients:manage` | Delete — cascades: consents removed, refresh families revoked, codes purged |

Validation (fail-closed): redirect URIs must be absolute, fragment-free and wildcard-free and are matched
**exactly** at authorize time; `grant_types` ⊆ `authorization_code|refresh_token|client_credentials`;
`scopes` ⊆ `openid profile phone`; public clients may not use `client_credentials`.

## Issuer Endpoints

All issuer routes are excluded from the OpenAPI schema; discovery document advertises every URL
(`SWX_OIDC_ISSUER` override or derived from the mounted prefix).

| Method | Path | Auth | Purpose |
|---|---|---|---|
| `GET` | `/oidc/authorize` | browser session / login redirect | Validate + store pending grant in session → login → issue code redirect |
| `POST` | `/oidc/token` | `client_secret_basic` / `client_secret_post` (public: secretless) | `authorization_code`, `refresh_token`, `client_credentials` |
| `POST` | `/oidc/revoke` | client authentication | RFC 7009 (200 even for unknown tokens — never leaks validity) |
| `GET` | `/oidc/userinfo` | Bearer (header only) | Scope-gated claims |
| `GET` | `/.well-known/openid-configuration` | public | OIDC Discovery 1.0 metadata |
| `GET` | `/jwks.json` | public | RFC 7517 JWKS (active + verify-only keys) |

## Flows

**Authorize → token (PKCE):**

1. `GET /oidc/authorize` validates client (enabled, grant allowed), redirect (exact membership), scope
   (subset), PKCE (`S256` only — `plain` refused) and requires `nonce` when `openid` is requested.
2. Unauthenticated users get a 303 to `SWX_OIDC_LOGIN_URL?next=<authorize url>` with the pending grant in
   the Starlette session; the user-domain session/cookie machinery performs authentication.
3. Post-authentication the code is issued (hash-stored, 60 s, single use), a consent row is recorded
   (trusted clients skip the screen but the row is still written), and the browser is redirected with
   `code` + `state`.
4. `POST /oidc/token` (`grant_type=authorization_code`) re-verifies the client, redirects (exact), consumes
   the code **atomically** (replay ⇒ `invalid_grant` + audit), verifies PKCE, then mints
   access + `id_token` + a refresh token (new family).

**Refresh rotation:** `refresh_token` grant verifies hash + expiry + `active` status; presents a reused
rotated/revoked token ⇒ **entire family revoked** + `auth.token_family_revoked` audit. Rotation is atomic
(single UPDATE + INSERT). `client_credentials` is confidential first-party only — machine token, no refresh,
no `id_token`.

## Token Lifecycle

| Token | Signing | `aud` | Lifetime | Revocation |
|---|---|---|---|---|
| access | RS256/EdDSA + `kid` header | `oidc_client:<client_id>` | client `access_token_ttl_seconds` | `/oidc/revoke` (JTI blacklist) or refresh-family revocation |
| refresh | opaque 48-byte urlsafe (SHA-256 stored) | n/a | client `refresh_token_ttl_seconds` | single token or whole family |
| id_token | RS256/EdDSA + `kid` header | `client_id` | client `id_token_ttl_seconds` | expiry only |

The `oidc_client:*` audience string means OIDC tokens can never be consumed as platform tokens and platform
tokens never pass OIDC checks (audience separation; see `swx_core/auth/core/jwt.py` — additive-only change).

## Key Management

```bash
swx idp rotate-keys [--algorithm RS256|EdDSA] [--retirement-days N] [--dry-run]
swx idp keys list
```

Rotation: the new key becomes the **only** `active` key; every previously active key is swept to
`verify_only` until `retires_at` (default 30 days) — old tokens verify to expiry, and JWKS keeps publishing
them so relying parties never break mid-window. Private PEMs are encrypted at rest via the EncryptionService
and are never present in any API response (`OIDCSigningKeyPublic` excludes them by type). Issuance fails
closed when no active key exists.

## Claims

`id_token` / userinfo claims: `iss`, `sub`, `aud`, `exp`, `iat`, `auth_time`, `nonce`, `azp`, `acr`, `amr`,
`at_hash`, `name` (scope `profile`), `phone` + `phone_verified` (scope `phone`; `phone_verified` reflects
`swx_users.phone_verified_at`). **No email claims, ever.**

Step-up evidence: `amr`/`acr` are stamped from the pending grant (`["pwd"]` default, `mfa` ⇒
`urn:swx:acr:mfa`) so consumers can gate on authentication recency.

## Phone Verification

```
POST /user/phone-verification/request   {"phone": "+2348012345678"}   # E.164 validated
POST /user/phone-verification/confirm    {"code": "<otp>"}             # flips phone_verified_at
```

Delivery is pluggable — register a `PhoneVerificationChannel` (e.g. the estate's WhatsApp channel) with
`register_phone_channel("whatsapp", channel)` and select it via `SWX_PHONE_VERIFICATION_CHANNEL`. OTP codes
reuse the email-OTP machinery (bcrypt-hashed, attempt-limited, cooldown-guarded) keyed `phone:<user_id>`.
`LoggingChannel` (default) logs the code for development.

## Identity Linking

Consumer products federate via the standard OAuth-consumer registry — add `afcloud` to `OAUTH_PROVIDERS`
with `AFCLOUD_*` env vars (`AFCLOUD_SERVER_METADATA_URL` preferred for discovery), zero code.

```python
from swx_core.auth.oidc_provider import link_external_identity, resolve_user_by_idp_sub

# login path
user = await resolve_user_by_idp_sub(session, idp_sub="afcloud-sub-123", idp="afcloud")

# account linking (Business Stage-1 one-click merge) — requires the IdP's verified-phone claim
account = await link_external_identity(session, user, idp_sub, idp="afcloud", phone_verified_claim=claims["phone_verified"])
```

Refusals (fail-closed): linking without `phone_verified=true`; subject already linked to a different user.

## CLI

```bash
swx idp rotate-keys [--algorithm] [--retirement-days] [--dry-run]
swx idp keys list
swx idp seed --demo        # 1 confidential + 1 public first-party demo client (idempotent)
swx idp bind-admin --admin-email a@b.c [--role admin]
```

## Hardening

- PKCE mandatory for all public clients; `plain` downgrade refused; constant-time challenge comparison
  (confidential clients may omit PKCE — OAuth 2.1 deviation codified as intentional, compensated by
  exact redirect + secret auth)
- Exact `redirect_uri` membership (no normalization/prefix); unknown clients and unregistered redirects are
  never redirected back to attacker-controlled URLs
- No client secrets via query string (400 before any other check); mixed authentication methods (Basic + body)
  refused per RFC 6749 §2.3; bcrypt verification with timing equalization (client enumeration hardened);
  terse `invalid_client` refusals (RFC 6749 §5.3.2)
- **Default rate limits ship** covering `/api/oidc/token|revoke|userinfo`, `/api/oidc/authorize` and
  `/api/admin/oidc` (override or opt out entirely via `SWX_AUTH_RATE_LIMIT_RULES`); canonical middleware
  stack (request-id, auth rate limiter, CSRF, session) applies globally
- Discovery + JWKS are excluded from the OpenAPI schema (prod docs-disabled mode consistent with the platform)
- Keys: DB-enforced single-active invariant (partial unique index); retirement enforced on the internal
  verification path (a retired kid stops verifying exactly when it drops from JWKS)
- Everything refuses **audited**: `auth.oidc_authorize_denied`, `auth.oidc_token_denied`,
  `auth.token_family_revoked`, `auth.oauth_key_rotated`, `auth.phone_verification_*`, `auth.identity_linked`

## Migrations

Standalone copy-in templates (set `down_revision` to your head):

| Revision | Content |
|---|---|
| `v2_30_0_oidc_provider_tables` | OIDC tables |
| `v2_30_1_social_account_identity_unique` | unique `(provider, provider_id)` on `swx_social_accounts` |
| `v2_30_2_admin_user_roles` | admin ↔ role bindings |
| `v2_30_3_user_phone_verification` | `swx_users.phone` + `phone_verified_at` |

Chained equivalents ship in the project scaffold (`swx_core/template/project/migrations/versions/`).

## Testing

`tests/auth/oidc/` + `tests/cli/test_idp_commands.py` — the conformance battery: authorize/token/userinfo/
revoke matrices (PKCE downgrade, redirect tampering, code replay, refresh reuse → family revocation, client
impersonation via direct `authenticate_client` tests, TTL boundaries), key rotation + JWKS, audience
back-compat, phone verification (real OTP machinery), identity linking. Regression parity for
`tests/security` + `tests/middleware/test_auth_rate_limit.py` is maintained.

---

**Related docs:** [AUTHENTICATION](AUTHENTICATION.md) · [OAUTH_PROVIDERS](OAUTH_PROVIDERS.md) ·
[ENTERPRISE_SSO](ENTERPRISE_SSO.md) · [RBAC](RBAC.md) · [AUDIT_LOGS](AUDIT_LOGS.md)