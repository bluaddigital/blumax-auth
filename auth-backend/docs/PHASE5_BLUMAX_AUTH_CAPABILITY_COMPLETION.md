# PHASE 5 — BLUMAX AUTH CAPABILITY COMPLETION

Date: 2026-10-02. Scope: `blumax-auth` (`auth-backend` and `src/blumax_auth`)
only. **Labs, Pharmacy, SuperAdmin, and Core were not modified.** Every
test ran against disposable Docker Postgres/Redis (`docker compose -p
p5-auth`, torn down at the end of this phase, including volumes). No
production or staging environment was touched. No production user was
migrated. No Core authentication was changed. No existing session was
invalidated — this service was not consuming production traffic before
this phase and still is not.

---

## A. Existing Core SSO architecture (audit, restated for this report)

Core's SSO lives in `app/core/sso_code.py` and four routes in
`app/modules/identity/api/routes.py`:

- `POST /auth/sso/code` — mint, called by an authenticated human.
- `POST /auth/sso/code/on-behalf` — mint, caller must be a service
  account; restricted via a hardcoded `MINT_ON_BEHALF_ALLOWED_SERVICES`
  set (today: only `"blumax-labs"`).
- `POST /auth/sso/exchange` — redeem, caller must be a service account;
  validates `destination_app` maps to the caller's own registered service
  name via a hardcoded `DESTINATION_APP_SERVICE_NAMES` dict; re-resolves
  the vouched-for user's claims fresh from Core's DB; returns an **access
  token only**, never a refresh token.
- `POST /auth/sso/code/consume` — redeem, public/unauthenticated,
  restricted to `destination_app ∈ {"admin","doctor"}`; mints a **full
  session** (access + refresh).

Code: `secrets.token_urlsafe(32)` (256 bits), stored in Redis as
`sso_code:{code}`, TTL 60s (`settings.SSO_CODE_TTL_SECONDS`), single-use
via atomic `GETDEL`, and — the one deliberate exception to Core's
otherwise universal fail-open posture — **fails closed** on a Redis
error.

## B. Existing service-token architecture (audit, restated)

`POST /auth/service-token`: `client_id`/`client_secret` → a row in Core's
`service_accounts` table. Each service account is a "shadow" `users` row
(`is_service=true`); authorization reuses the exact human machinery
(`user_tenant_memberships` + `role_id` + `role_permissions`) — no
separate scopes column exists. The resulting token shares the human
`AccessTokenClaims` shape with two differences: `type="service"` (not
`"access"`) and `snm=<service name>`. No permission list is embedded;
`GET /api/v1/me/permissions` resolves permissions live (60s cache) for
both human and service callers. Service tokens are short-lived (10
minutes) versus a human token's ~24h rolling lifetime.

## C. Existing password lifecycle (audit, restated)

Core: create user (identity module), `/auth/login` (bcrypt via passlib,
constant-time), `/auth/change-password`, a `must_change_password`/
temporary-password flag on the user row, account `is_active` status, and
an IP-keyed login rate limiter. No forgot-password/reset-by-code flow was
found in Core's identity module during the prior audits of this
engagement (not re-verified in this phase — Core was not touched or
re-read). Account-level lockout is a named, deliberately-deferred item in
both Core's and this service's own `rate_limit.py` docstrings, not
silently skipped.

## D. Existing Blumax Auth capability (before this phase)

Confirmed by direct inspection at the start of this phase: `/auth/login`,
`/auth/refresh`, `/auth/logout`, `/auth/me`, `/.well-known/jwks.json`,
`/health`. Exactly two DB tables (`users`, `refresh_tokens`). JWT claims
exactly 7 (`iss`/`aud`/`sub`/`type`/`jti`/`iat`/`exp`), `type` hardcoded to
`Literal["access","refresh"]` — structurally unable to mint a third type
without a code change. Logout wrote a Redis revocation marker under a
**different key name** (`auth_session_revoked_at:*`) than the shared
`blumax_auth` library's consumer-side check expects (`session_revoked_at:
*`, Core's format) — a real, silent-failure bug, not a design gap. No
SSO, no service-to-service auth, no password-reset flow, no
production-facing user-creation API (only a dev-only CLI script) existed
anywhere in this service.

## E. Security gaps (found, and their disposition this phase)

| Gap | Disposition |
|---|---|
| Revocation key-name mismatch | **Fixed** (§O) — renamed to `session_revoked_at:*`, now byte-identical to Core's and the shared library's format. |
| No SSO capability | **Built** (§F/§G) — reimplemented against this service's own architecture, not copied. |
| No service-to-service auth | **Built** (§F/§G) — a genuinely new, separate id space (not a "shadow user"), with explicit least-privilege scopes. |
| No password-reset flow | **Built** (§G) — code-based, reusing the SSO code's own proven Redis primitive. |
| No production user-creation API | **Built** (§G) — `/admin/identities/*`, scope-gated. |
| Revocation marker had no TTL | **Fixed** — now expires after `SESSION_REVOCATION_TTL_SECONDS` (26h, mirroring Core's own margin), bounding otherwise-unbounded Redis growth. |
| Service-token claims could duplicate human claims by accident | **Avoided by design** — `ServiceTokenClaims` is a distinct class with exactly two differences from `TokenClaims` (`type="service"`, `snm`), never a tenant/role/scope claim. |

## F. Proposed Blumax Auth architecture (implemented this phase)

```
                        BLUMAX AUTH
              (identity / authentication / SSO)
         ___________________|___________________
        |                                        |
   Human identity                         Service identity
   (users table,                          (service_accounts table,
    unchanged since                        NEW — its own id space,
    Phase 1)                               never a "shadow user")
        |                                        |
   /auth/login                             /auth/service-token
   /auth/refresh                                 |
   /auth/logout                            least-privilege scopes,
   /auth/change-password        NEW        checked server-side at
   /auth/password-reset/*       NEW        mint/exchange time, never
   /admin/identities/*          NEW        embedded in the JWT:
        |                                   - destination_app (exchange)
        |                                   - may_mint_on_behalf +
   /auth/sso/code         NEW                 allowed_mint_destinations
   /auth/sso/code/on-behalf NEW              - may_manage_identities
   /auth/sso/exchange     NEW                      |
   /auth/sso/code/consume NEW               (shares the SAME Redis-
        |                                    backed, GETDEL, fail-
   (shares the SAME RS256                     closed SSO-code primitive)
    keys.py signing/JWKS/
    rotation machinery every
    other token type already used)
```

Every application (Admin/Core/OPD/IPD/Labs/Pharmacy — any current or
future one) is a potential SSO destination; none is hardcoded the way
Core's `DESTINATION_APP_SERVICE_NAMES`/`MINT_ON_BEHALF_ALLOWED_SERVICES`
dicts are — which services may mint/exchange for which destinations is
data (`ServiceAccount` rows), not code, so onboarding a new application
never requires a Blumax Auth code change.

**Not blindly copied from Core** — three deliberate departures, each
justified:
1. A service account is its own table/id space, not a `users` shadow row
   (Blumax Auth has no tenant/role model to piggyback on the way Core
   does — see `app/models/service_account.py`'s own docstring).
2. Least-privilege scopes are explicit, narrow, independent booleans/
   lists per capability (`destination_app`, `may_mint_on_behalf` +
   `allowed_mint_destinations`, `may_manage_identities`) — never a single
   do-everything flag, and never embedded in the resulting JWT.
3. `change_password`/`confirm_password_reset` never mint a replacement
   token in the same call — they revoke every session and return 204,
   sidestepping the classic self-logout race entirely instead of needing
   a jti-exemption mechanism.

## G. Exact APIs/endpoints (all new this phase, except where noted)

| Method & path | Caller | Request | Response | Notes |
|---|---|---|---|---|
| `POST /auth/service-token` | any service | `{client_id, client_secret}` | `{access_token, token_type, expires_in}` | Rate-limited by IP. |
| `POST /auth/sso/code` | human (Bearer access token) | `{destination_app}` | `{code, expires_in}` | Mints for the caller's own `sub` only. |
| `POST /auth/sso/code/on-behalf` | service (Bearer service token) | `{user_id, destination_app}` | `{code, expires_in}` | Requires `may_mint_on_behalf` + `destination_app ∈ allowed_mint_destinations`. |
| `POST /auth/sso/exchange` | service (Bearer service token) | `{code}` | `{access_token, token_type, expires_in}` | Requires `destination_app == caller.destination_app`. Access token only. |
| `POST /auth/sso/code/consume` | public, unauthenticated | `{code}` | `{access_token, refresh_token, token_type}` | Restricted to `SSO_PUBLIC_CONSUME_DESTINATION_APPS`. |
| `POST /auth/change-password` | human (Bearer access token) | `{current_password, new_password}` | 204 | Revokes all sessions; does not re-mint. |
| `POST /auth/password-reset/request` | public | `{identifier}` | 202, identical shape regardless of existence | Dev-mode-only: includes `dev_reset_code`. |
| `POST /auth/password-reset/confirm` | public | `{reset_code, new_password}` | 204 | Single-use, revokes all sessions. |
| `POST /admin/identities` | service (`may_manage_identities`) | `{identifier, password?}` | 201 `{id, identifier, is_active, temporary_password?}` | 409 on duplicate identifier. |
| `GET /admin/identities/{id}` | service (`may_manage_identities`) | — | `{id, identifier, is_active, created_at}` | Never returns the hash. |
| `POST /admin/identities/{id}/activate` | service (`may_manage_identities`) | — | 204 | |
| `POST /admin/identities/{id}/deactivate` | service (`may_manage_identities`) | — | 204 | Revokes all sessions immediately. |
| `POST /admin/identities/{id}/set-password` | service (`may_manage_identities`) | `{new_password}` | 204 | Revokes all sessions. |

`/auth/login`, `/auth/refresh`, `/auth/logout`, `/auth/me`,
`/.well-known/jwks.json`, `/health` are unchanged from Phase 1.

## H. Exact JWT contracts

Human access/refresh — unchanged since Phase 1:
```
{ "iss", "aud", "sub", "type": "access"|"refresh", "jti", "iat", "exp" }
```

Service — new, documented claim-by-claim in `ServiceTokenClaims`'s own
docstring (`app/core/security.py`):
```
{ "iss", "aud", "sub": <ServiceAccount.id>, "type": "service",
  "snm": <ServiceAccount.name>, "jti", "iat", "exp" }
```
`sub` is a **separate UUID space** from human `users.id` (a different
table, a different generator) — it can never collide with or be mistaken
for a human subject even before `type` is checked. `snm` is audit/logging
only, never authorization — every scope check happens server-side against
the live `ServiceAccount` row at the moment of the action (SSO
mint/exchange, identity management), never by trusting a claim on the
token. No tenant/role/facility/permission claim was added to either
contract, per explicit instruction.

## I. Redis data model

| Key | Written by | Read by | TTL | Purpose |
|---|---|---|---|---|
| `session_revoked_at:{user_id}` | `revoke_user_sessions` (logout, password change/reset, deactivate) | `is_session_revoked` (this service's own `/auth/me` and `verify_access_token`); the shared `blumax_auth` library's `check_session_revocation` (a downstream consumer, once it points at this Redis) | `SESSION_REVOCATION_TTL_SECONDS` (26h) | Per-user logout/revocation marker. **Format now matches Core's exactly** (§D/§E). |
| `sso_code:{code}` | `mint_code` | `consume_code` (atomic `GETDEL`) | `SSO_CODE_TTL_SECONDS` (60s) | Single-use SSO authorization code. |
| `password_reset_code:{code}` | `mint_reset_code` | `consume_reset_code` (atomic `GETDEL`) | `PASSWORD_RESET_TTL_SECONDS` (15m) | Single-use password-reset code. |
| `rate_limit:login:{ip}`, `rate_limit:service-token:{ip}`, `rate_limit:password-reset:{ip}` | `check_rate_limit` | same | fixed window (`LOGIN_RATE_LIMIT_WINDOW_SECONDS`) | IP-keyed throttling, unchanged mechanism, reused for the two new endpoints. |

No key format was invented without a reason: the session-revocation
format was corrected to MATCH an existing one; the SSO-code and
password-reset-code formats are deliberately the SAME primitive under
different prefixes, not two separate mechanisms.

## J. Identity migration strategy

Verified directly against the actual schemas in this phase (not merely
recommended in a prior audit):
- Blumax Auth's `users.id` has **no DB-level default, CHECK constraint,
  or trigger** — only a Python-side `default=uuid.uuid4()` that an
  explicit insert bypasses cleanly (confirmed by
  `migrations/versions/001_initial.py`: only a primary key and a unique
  index on `identifier`).
- `app/services/identity_service.py::create_identity_with_id` performs
  exactly that explicit-id insert, with duplicate-identifier detection.
- `scripts/migrate_core_user.py` is the migration **design**: reads a
  Core-shaped export (`--source-json`; `--source-db-url` is accepted as a
  future input but not wired to a live Core connection in this phase,
  since no Core database access is available to this service or its
  tests), classifies every row as **to-insert**, **already-present**
  (idempotent — a second run never duplicates or errors), or
  **identifier-conflict** (flagged for manual review, never silently
  overwritten), and only writes anything when `--execute` is passed —
  default is a dry run.
- `tests/test_migration_script.py` exercises this plan/apply logic
  directly against the test database (fresh rows, idempotent re-run,
  conflict detection) — proving the DESIGN works, without ever touching
  a real Core database, per this phase's explicit scope.
- `tests/test_identity_migration_compat.py` proves, in executable code,
  that a bcrypt hash produced by the **raw `bcrypt` library** (the way
  Labs/Core hash passwords) verifies through Blumax Auth's **passlib**-
  based `verify_password` with zero conversion, and the reverse direction
  too — the concrete evidence behind the Phase 4A report's compatibility
  claim.

**This phase did not execute any migration against any real data.**

## K. Rollback strategy

Nothing in this phase changed any consumer's `AUTH_PROVIDER` default
(still `"core"` everywhere it exists) or activated anything in
production. Within Blumax Auth itself, every new capability is additive:
new tables, new routes, new Redis key prefixes under namespaces nothing
previously used. The one in-place behavior change — the revocation
key-name fix — has no observable rollback concern, since nothing consumed
the old (buggy) key name in production (confirmed: no consumer calls
`configure_session_revocation` against this service today). If any new
endpoint needed to be pulled, removing its router line from `app/main.py`
fully restores Phase 1/3C behavior with zero impact on `/auth/login`,
`/auth/refresh`, `/auth/logout`, `/auth/me`, JWKS, or health.

## L. Security threat model

- **SSO code theft/replay**: 256-bit entropy, 60s TTL, atomic single-use
  consumption (proven against real Redis with concurrent `asyncio.gather`
  calls, not just reasoned about), fail-closed on Redis error. An
  intercepted-but-unconsumed code is useless after 60 seconds or one use,
  whichever comes first.
- **Wrong-destination exchange**: a service account can only exchange
  codes for its own registered `destination_app`; cross-application
  exchange (e.g. a Pharmacy-registered account redeeming a Labs-destined
  code) is rejected with the same generic 401 as every other SSO failure
  mode, so an attacker cannot distinguish "wrong destination" from
  "expired" from "already used."
- **Mint-on-behalf abuse**: gated by two independent conditions
  (`may_mint_on_behalf` AND the specific `destination_app` being in
  `allowed_mint_destinations`) — a service compromised or misconfigured
  for one destination cannot mint codes for a different one.
- **Service/human token confusion**: `decode_token`'s `expected_type`
  parameter is mandatory at every call site; a human token presented
  where a service token is required (and vice versa) is rejected before
  any business logic runs — proven directly by test, both directions.
- **Algorithm/key confusion** (alg=none, RS256→HS256 downgrade, forged
  kid, wrong signature): service tokens flow through the exact same
  `decode_token`/`TokenVerifier`-equivalent path as human tokens, so every
  protection Phase 1 already proved for human tokens applies identically
  — confirmed by a parallel set of tests for `type="service"`, not merely
  assumed from code-sharing.
- **Password-reset account enumeration**: identical response shape and
  status code regardless of whether the identifier exists; the dev-mode
  `dev_reset_code` field is the one deliberate, explicitly-flagged
  exception, never present in production (`settings.is_production`
  gated).
- **Deactivation-after-mint**: every service-token-gated action re-loads
  the `ServiceAccount` row fresh from the database rather than trusting
  the token alone — a deactivated-after-mint account is rejected on its
  very next use even though its short-lived token hasn't expired,
  confirmed by test.
- **Self-logout race on password change**: avoided structurally (§F),
  not patched around.

## M. Test plan (executed this phase)

All against **real** Postgres + Redis (disposable, torn down after), real
RS256 signing keys, real HTTP requests through the FastAPI app — never
mocked at the HTTP layer; Redis/network failures are simulated only where
the brief specifically asked for a failure-mode test (`monkeypatch`
raising inside the Redis client, the sole mocking in the whole suite).

| Area | Covered |
|---|---|
| SSO | valid exchange, exchange never returns a refresh token, expired code (real TTL expiry, not simulated), replayed code, wrong destination, service with no destination at all, random invalid code, Redis unavailable (mint and consume, both at the primitive level and at the HTTP route level), **concurrent consumption against real Redis** (`asyncio.gather`, exactly one of three parallel attempts succeeds), mint-on-behalf denied without scope, denied for an unlisted destination, succeeds for an allowed one, denied for an unknown user, human token rejected on service-only routes, service token rejected on human-only routes. |
| Service tokens | valid issuance, wrong client_secret, unknown client_id (identical error to wrong secret), inactive account, claim-set exactness (`snm`/`type`, nothing else), deactivated-after-mint rejected on next use, wrong audience, wrong issuer, expired, unknown kid, wrong signature (real different key, real matching kid), wrong-type-presented-as-access and vice versa. |
| Password | change (valid, wrong current, too short, revokes existing sessions including the caller's own), reset request + confirm, unknown identifier gets identical response, expired reset code, reused reset code, inactive-account reset is a no-op, confirm with too-short password rejected, reset-request rate limiting. |
| Identity admin | create, create without password returns a temp password, duplicate identifier rejected, missing-scope rejected, get, get-unknown 404, deactivate blocks login, deactivate revokes an already-issued session immediately, activate reverses it, admin set-password, too-short password rejected. |
| Identity migration | preserved-UUID insert round-trips, duplicate-identifier-during-migration rejected, raw-bcrypt hash verifies through passlib with zero conversion (both directions), migration script's plan/apply logic (fresh/idempotent/conflict) against the test database. |
| JWT (service-token dimension, mirroring Phase 1's existing human-token suite) | alg=none-equivalent structural rejection (via the shared `decode_token` path, already proven for humans and re-confirmed for `type="service"`), RS256→HS256 confusion already covered by Phase 1's `test_jwt.py` for the underlying verifier and re-confirmed here does not special-case service tokens, forged kid, wrong signature, expired, wrong issuer, wrong audience — all for `type="service"` specifically. |

## N. Implementation status

Fully implemented and tested, not deployed, not activated by any
consumer. **95/95 tests passing** — 33 pre-existing (confirmed unchanged
behavior) + 62 new. Both new operational scripts
(`provision_service_account.py`, `migrate_core_user.py`) were smoke-tested
end-to-end against the disposable database (create, rotate-secret, and a
migration dry run all produced correct output) in addition to their
automated test coverage.

## O. Files changed

- `app/core/config.py` — new settings (`SESSION_REVOCATION_TTL_SECONDS`,
  `SERVICE_TOKEN_EXPIRE_MINUTES`, `SSO_CODE_TTL_SECONDS`,
  `SSO_PUBLIC_CONSUME_DESTINATION_APPS`, `PASSWORD_RESET_TTL_SECONDS`,
  `PASSWORD_MIN_LENGTH`).
- `app/core/security.py` — widened `TokenType`, added `ServiceTokenClaims`
  and `create_service_token`; `decode_token`'s signature generalized to
  accept the new type (its body was already type-generic).
- `app/core/session_revocation.py` — key-prefix fix (§D/§E) + TTL added.
- `app/core/sso_code.py` — **new**.
- `app/core/password_reset.py` — **new**.
- `app/models/service_account.py` — **new**.
- `app/models/__init__.py`, `migrations/env.py` — register the new model.
- `migrations/versions/002_service_accounts.py` — **new**.
- `app/schemas/sso.py`, `service_account.py`, `identity.py`, `password.py`
  — **new**.
- `app/services/sso_service.py`, `service_account_service.py`,
  `identity_service.py`, `password_service.py` — **new**.
- `app/api/deps.py` — added `bearer_token`, `require_human_user_id`,
  `require_service_account`.
- `app/api/sso_routes.py`, `service_routes.py`, `password_routes.py`,
  `identity_routes.py` — **new**.
- `app/main.py` — wires the four new routers in.
- `.env.example` — documents the new settings.
- `scripts/provision_service_account.py`, `migrate_core_user.py` — **new**.
- `scripts/create_dev_user.py` — docstring cross-reference only, no
  behavior change.
- `tests/conftest.py` — added a `make_service_account` factory fixture.
- `tests/test_sso.py`, `test_service_token.py`,
  `test_password_management.py`, `test_identity_admin.py`,
  `test_identity_migration_compat.py`, `test_migration_script.py` —
  **new**.
- `docs/PHASE5_BLUMAX_AUTH_CAPABILITY_COMPLETION.md` — this report.

## P. Files not changed

`app/api/routes.py`, `app/core/keys.py`, `app/core/rate_limit.py`,
`app/core/database.py`, `app/models/user.py`, `app/models/refresh_token.py`,
`app/services/auth_service.py`, `app/schemas/auth.py`,
`migrations/versions/001_initial.py`, every pre-existing test file
(`test_login.py`, `test_refresh.py`, `test_session.py`, `test_jwks.py`,
`test_jwt.py`, `test_security.py`, `test_backward_compat.py`),
`docker-compose.yml`, `Dockerfile`, `pyproject.toml`. Every file in
`blumax-labs`, `blumax-pharm`, `blumax-superadmin`, and `blumax-backend`
(Core) — confirmed by a five-repository `git status` check at the end of
this phase; Core, Labs, Pharmacy, and SuperAdmin show only their own
pre-existing, unrelated state from other work on this shared dev-server
host, none of it touched or created by this phase.

## Q. Production safety assessment

Safe. Nothing in this phase is reachable by any production or staging
traffic — `blumax-auth`'s `auth-backend` has never been deployed or
pointed at by any consumer (confirmed across every phase of this
engagement). All testing used disposable, project-scoped Docker
infrastructure (`p5-auth`), torn down with its volumes at the end of this
phase. No `.env` file was created or left behind. No production secret,
key, or credential was read, generated, or logged. No consumer's
`AUTH_PROVIDER` was touched.

## R. Exact next phase

**Do not proceed to consumer migration yet** — per this phase's own
explicit instruction, Labs, Pharmacy, SuperAdmin, and Core all remain
exactly as they were. The next phase is **Labs migration** (per the
stated order: Labs, then Pharmacy, then SuperAdmin's final production
cutover if still required, then Core-authentication removal), scoped to
the small, already-identified code changes Phase 4A's own report deferred:
repoint `core_login.py`'s password delegation and `core_client.py`'s SSO
redeem/mint-outbound at this service's newly-built equivalents, gated by
the existing `AUTH_PROVIDER` toggle, proven first in DEV with a bulk-
copied subset of real identities (one per user category) before any
production user is touched — exactly the sequencing this phase's
capability work was built to unblock, not to shortcut.

---

### STOP conditions — none triggered

Checked explicitly, per the brief's own list: no production data was
modified; no production user was invalidated; no existing Core token
behavior changed (Core was not touched at all); no breaking change was
made to the human JWT contract (unchanged since Phase 1); no Core database
dependency was introduced anywhere in this service; tenant/role/facility
authorization was not moved into Blumax Auth (it still has none, by
design); Core's bcrypt hashes were proven compatible, not found
incompatible; every SSO design decision needed (destination-app scoping,
mint-on-behalf scoping, access-token-only exchange) was inferable
directly from Core's own already-proven, already-audited implementation,
not invented from nothing; every service-token scope implemented here is
least-privilege by construction (three independent, narrow capabilities,
never a single broad flag).
