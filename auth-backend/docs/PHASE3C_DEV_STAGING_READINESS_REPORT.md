# PHASE 3C — BLUMAX AUTH DEV/STAGING READINESS REPORT

Date: 2026-10-02
Scope: Blumax Auth only (`blumax-auth/auth-backend`). No other repository was
modified. No production system was touched. No production secret or key was
created, rotated, or reused.

---

## 1. Current architecture

Blumax Auth is a standalone FastAPI service (`app/main.py`) with three
dependencies: Postgres (users, refresh tokens), Redis (rate limiting, session
revocation), and an RS256 signing key. It exposes:

- `POST /auth/login`, `/auth/refresh`, `/auth/logout`, `GET /auth/me`
- `GET /.well-known/jwks.json`
- `GET /health`

It issues a deliberately thin, identity-only JWT (iss/aud/sub/type/jti/iat/exp
— no tenant_id/role/archetype/facility_id/permissions), per the Phase 1
decision. It does not yet issue or verify any business claim, and per this
engagement's explicit charter, must not gain one without a dedicated
architecture review.

## 2. Infrastructure architecture

Three containers (`postgres`, `redis`, `app`) on an isolated bridge network
(`blumax-auth-net`), defined in `docker-compose.yml`. This compose file is
entirely self-contained — no link to Core's database, Core's Redis, or
`blumax-platform`'s compose files, and is not wired into dev-infra. It is a
disposable-by-default definition that this phase upgraded with persistent
named volumes (see §4) so that a *deliberately* kept-running instance behaves
like a real dev/staging service rather than scratch infrastructure.

## 3. Database (Postgres) persistence

`auth_pgdata` is a named Docker volume mounted at
`/var/lib/postgresql/data`. Verified live this phase: a full
`docker compose down && up` (container + network removal, network/container
objects recreated from scratch) preserved all rows — the bootstrapped test
user could still log in afterward with the same password hash, and
`alembic current` still reported `001_initial (head)` with `upgrade head`
re-run producing no further output (a clean, idempotent no-op). This is
already the correct persistence pattern; no change was needed here beyond
confirming it holds under real recreation, not just a plain restart.

## 4. Redis persistence

`auth_redisdata` is a named volume mounted at `/data`, with
`redis-server --appendonly yes` (AOF persistence enabled, not just RDB
snapshotting) already set in `docker-compose.yml` from Phase 1. Redis here
holds two kinds of state: (a) login rate-limit counters — inherently
short-lived, fine to lose; (b) session-revocation markers — losing these on
a Redis restart would silently un-revoke an already-logged-out session for
the remainder of its access-token lifetime (currently ≤15 minutes). AOF
persistence bounds that exposure to "whatever wasn't fsynced yet," which is
an acceptable DEV/STAGING risk and already the right default; this phase
made no code change here, only confirmed (via the recreation test) that the
volume mount is real, not accidentally anonymous.

## 5. Signing-key persistence and rotation lifecycle

**This was the one real defect found and fixed this phase.**

Finding: the dev-mode signing key (`app/core/keys.py::_load_or_create_dev_key`,
written to `JWT_DEV_KEY_PATH=".dev-keys/auth-jwt-private.pem"`) lived only in
the container's writable layer. It survived a plain `docker restart` but
**not** `docker compose down && up` or any container recreation — which would
silently generate a brand-new key (and therefore a new `kid`) and invalidate
every previously-issued token platform-wide, with no error or warning
anywhere.

Fix: a named volume, `auth_devkeys:/app/.dev-keys`, added to the `app`
service plus a Dockerfile change (`RUN mkdir -p /app/.dev-keys && chown -R
appuser:appgroup /app`, executed **before** `USER appuser`) so the mount
point already exists with correct non-root ownership in the image layer
before the volume mounts over it — otherwise Docker creates a fresh,
root-owned directory at that path on first mount, which the non-root
`appuser` cannot write to (`PermissionError: [Errno 13]`), a trap documented
inline in the Dockerfile.

This fix is irrelevant in production, which requires the real
`JWT_PRIVATE_KEY` env var and **refuses to start** without it
(`keys.py`'s own production guard, unchanged) — the volume only matters for
the dev-key fallback path, i.e. exactly DEV/STAGING.

**Live proof executed this phase** (ephemeral project `p3c-auth`, torn down
afterward):
1. Started the stack, bootstrapped a user, confirmed `/health` reports all
   three dependencies `ok`, confirmed JWKS with `kid=e2e09f279a124688`.
2. Logged in for real (actual `/auth/login` call, not a hand-minted token),
   saved the access token, confirmed `GET /auth/me` → 200.
3. `docker compose down` (full container+network removal) then
   `docker compose up -d` (full recreation).
4. Post-recreation: health still all-`ok`, **`kid` identical**
   (`e2e09f279a124688`) — the critical proof.
5. The pre-recreation access token still verified correctly post-recreation
   (`GET /auth/me` → 200, correct claims).
6. Login still worked post-recreation (Postgres data intact).
7. `alembic current` → `001_initial (head)`; `alembic upgrade head` →
   clean no-op (migrations remain consistent across recreation).

**Controlled key-rotation test** (separate ephemeral project `p3c-rotate`,
torn down afterward), proving the explicitly-requested overlap window:
1. Captured the pre-rotation `kid` (`3345ea241fd35773`) and a real
   login-issued access token.
2. Extracted that key's public half, removed the persisted private-key file
   from the volume (forcing regeneration), and set
   `JWT_PREVIOUS_PUBLIC_KEY` to the old public key PEM.
3. Recreated the `app` container.
4. `GET /.well-known/jwks.json` now published **two** keys: a new current
   `kid=0c9cee0788d233f1` and the old `kid=3345ea241fd35773`.
5. The token issued **before** rotation (signed with the retired key) still
   verified successfully via `/auth/me` → 200 — proving old tokens remain
   valid through the overlap window.
6. A fresh login **after** rotation issued a token signed with the new key
   (confirmed via its JWT header) and that token also verified → 200 —
   proving the new key is immediately usable.

**Documented lifecycle** (mirrors Core's own rotation pattern, by design,
per `keys.py`'s own module docstring):
1. Generate a new key pair; keep the old private key available only long
   enough to let in-flight tokens expire (bounded by access-token TTL, ≤15
   min, plus clock skew).
2. Deploy with the **new** key as `JWT_PRIVATE_KEY` (or let dev-mode
   regenerate it) and the **old** public key as `JWT_PREVIOUS_PUBLIC_KEY`.
   JWKS now publishes both `kid`s simultaneously.
3. Both old-signed and new-signed tokens verify during this window — proven
   above.
4. After the old key's longest-lived token type has fully expired (refresh
   tokens, 14 days, are the long pole — access tokens alone would only need
   the ≤15-minute window), drop `JWT_PREVIOUS_PUBLIC_KEY`. JWKS reverts to
   publishing one key.
5. Destroy the old private key material. It was never required by the
   verification path — only `JWT_PREVIOUS_PUBLIC_KEY` (public half) ever
   needs to exist post-rotation.

No code change was needed to support rotation — `SigningKeys` already
supported exactly this in Phase 1; this phase only proved it live.

## 6. Environment / secrets classification

| Item | DEV | STAGING | PRODUCTION | Class |
|---|---|---|---|---|
| `JWT_PRIVATE_KEY` | unset (auto dev-key) | **must be set**, generated for staging only, never shared with prod | must be set, HSM/secrets-manager sourced | Signing key — never committed, never logged |
| `JWT_PREVIOUS_PUBLIC_KEY` | set only during a rotation drill | same | same | Public key — not secret, but integrity-sensitive (wrong value breaks verification) |
| `JWT_DEV_KEY_PATH` | `.dev-keys/auth-jwt-private.pem` (volume-backed) | unused (real key required) | unused, and actively refused if reached (`is_production` guard) | Dev-only convenience, not a secret-management mechanism |
| `DATABASE_URL` | local compose Postgres, throwaway creds | staging-dedicated Postgres, distinct creds from prod | managed Postgres, rotated creds via secrets manager | DB credential |
| `REDIS_URL` | local compose Redis | staging-dedicated Redis | managed Redis | Infra credential |
| `JWT_ISSUER` / `JWT_AUDIENCE` | `https://auth.blumax.health` / `blumax` (fixed contract value, not secret) | same values | same values | App setting — must stay byte-identical across environments, since it's a frozen contract (§9) |
| `SESSION_REVOCATION_FAIL_MODE` | `closed` | `closed` | **explicit decision needed before cutover** — differs from Core's confirmed fail-open default; not yet signed off for prod | App setting, security-relevant |
| `ENVIRONMENT` | `development` | `staging` | `production` | App setting — the single toggle that activates the production guard in `keys.py` |

No production secret exists in this repository, this phase's compose file,
or anywhere referenced by it. Every credential used in all live testing this
phase was a throwaway, compose-local value (`authuser`/`authpass`, etc.),
destroyed with the containers.

## 7. Networking / HTTPS readiness (plan only — not implemented)

- **DNS**: `auth.blumax.health` is already the frozen `JWT_ISSUER` value;
  staging should use a distinct hostname (e.g. `auth-staging.blumax.health`)
  with its **own** `JWT_ISSUER`/key pair — issuer values must never be
  shared between environments, or a staging-issued token would verify
  against production JWKS and vice versa.
- **Reverse proxy / TLS termination**: not yet defined for this service;
  should follow the same nginx-in-front-of-service pattern already used
  platform-wide (`blumax-platform`'s nginx config), terminating TLS before
  traffic reaches the `app` container — no change needed inside this repo
  for that, only an nginx server block added at the platform layer when
  this service is actually deployed there (out of scope for this phase,
  which explicitly must not touch `blumax-platform` or deploy anything).
- **CORS / trusted origins**: not yet configured in `app/main.py` — needed
  before any browser-based consumer (vs. server-to-server) talks to this
  service directly; currently every consumer (Superadmin backend) calls it
  server-side, so this is a forward-looking gap, not a current blocker.
- **Firewalling**: Postgres/Redis ports are *not* exposed to the host in the
  shipped `docker-compose.yml` (confirmed this phase — only `app`'s 8040 is
  published, and only to `127.0.0.1`); this is the correct default and
  should stay true at every environment tier.

## 8. Health checks and observability

`/health` (fixed this phase) distinguishes the three real dependencies —
database, Redis, signing key — and returns a genuine `503` if any one is
unavailable, unlike the blanket-200 pattern flagged in an earlier audit of
Core's and Superadmin's own health endpoints. Verified live: reported
`{"status":"ok","database":"ok","redis":"ok","signing_key":"ok"}` both before
and after full container recreation.

Logging: confirmed (by code inspection of `auth_service.py`,
`security.py`, `session_revocation.py`) that no password, private key,
refresh-token value, or access-token value is ever interpolated into a log
line — `session_revocation.py` logs loudly on fail-mode decisions but only
user/session identifiers, never token material. No new logging was added or
needed this phase.

## 9. Frozen JWT contract (Phase 1, restated unchanged)

```
{
  "iss": "https://auth.blumax.health",
  "aud": "blumax",
  "sub": "<user id>",
  "type": "access" | "refresh",
  "jti": "<uuid>",
  "iat": <int>,
  "exp": <int>
}
```

No tenant_id, role, archetype, facility_id, or permission claim. This
contract is unchanged by Phase 3C — nothing in this phase touched
`security.py`'s token-building code. Any future addition (including the
`session_epoch`-style claim discussed in §10 below) requires the same kind
of explicit, dedicated decision Phase 1's thin-token choice went through —
not a silent addition.

## 10. Cross-service logout architecture — options analysis (decision only, not implemented)

| | A. Short-lived access tokens | B. Consumer-side introspection | C. Central revocation lookup | D. Revocation events | E. Token/session-version claim | F. Combination |
|---|---|---|---|---|---|---|
| **Mechanism** | Shrink access-token TTL; staleness self-bounds | Every request calls Auth's `/auth/me` or an introspection endpoint | Every request does a Redis GET against a shared revocation store | Auth publishes a logout/revoke event; consumers keep a local, async-updated cache | New claim (e.g. `session_epoch`) compared against a locally-synced current value | A baseline + an upgrade path |
| **Security** | Good — bounds exposure to TTL | Best — always current | Near-best | Good — bounded by propagation lag (sub-second) | Good — same bound as D | Matches whichever components are combined |
| **Performance** | No new cost | Worst — a synchronous network round-trip on *every* authenticated request, for *every* service | A Redis GET per request — cheap but still synchronous and new | No per-request cost — local cache read | No new cost — piggybacks on a lookup services already do | Depends |
| **Availability** | No new dependency | Auth becomes a hard synchronous dependency for every request, platform-wide | New synchronous Redis dependency for every consumer | Degrades gracefully — stale-but-available on event-stream hiccup | Degrades gracefully, same as D | Depends |
| **Coupling** | None | Severe — exactly the "Pharmacy/Labs must reach Core live" anti-pattern this platform has deliberately moved away from elsewhere | Moderate-high — every consumer gains a new Redis dependency on Auth specifically | Low — reuses the exact outbox/relay/event pattern already used platform-wide for provisioning/role-sync | Low — reuses an existing per-request local lookup each consumer already performs | Depends |
| **Complexity to build** | Trivial — a config value, already supported today | Moderate | Moderate | Moderate — new event type + consumer-side cache in each of 4 services | Moderate-high — new claim, new column on each consumer's local identity table, plus the claim needs its own architecture sign-off (§9) | Depends |
| **Suitability: Core/Superadmin** | Good | Acceptable (already server-to-server, least harmed by B) | Acceptable | Good | Good | — |
| **Suitability: Pharmacy/Labs** | Good | **Bad** — reintroduces a live dependency on an external service for every request, which Pharmacy/Labs' entire architecture (database-per-tenant, local enforcement, graceful-degradation-from-Core) was built specifically to avoid | Bad-to-acceptable — new infra dependency neither currently has | Good — matches the sync pattern they already use for patient/provider/role data | Good, if claim is approved | — |

**Recommendation: F — adopt A now; treat D as the architecturally-correct
longer-term upgrade if a sub-second cross-service logout requirement is ever
stated.**

- **A is being recommended as the only in-scope action**, because it is the
  one option the Phase 3C brief's own constraint ("do NOT implement unless
  already clearly supported by the current architecture and requires only a
  safe configuration/documentation change") actually licenses: tightening
  `ACCESS_TOKEN_EXPIRE_MINUTES` is a pre-existing `Settings` field, already
  fully supported, requiring no code change. This report does **not**
  change the shipped default — that is a product judgment call for the
  user, not mine to make unilaterally — it documents the value as a
  deployment-time recommendation only (e.g. consider 5 minutes rather than
  15 for staging/production once a real logout-latency requirement exists).
- **D is the recommended target if stronger guarantees are ever needed**,
  because it is the only other option that doesn't reintroduce the exact
  synchronous-coupling anti-pattern this whole multi-phase migration has
  been deliberately removing elsewhere (OPD↛Billing, Pharmacy/Labs'
  database-per-tenant isolation, the existing provisioning/role-sync relay
  family). It is **not implemented in this phase** — it requires new event
  types and new consumer-side cache logic in up to 4 services, well beyond
  "safe config/doc change."
- **B and C are not recommended** — both would make Blumax Auth (or its
  Redis) a hard, synchronous, per-request dependency for Core, Pharmacy,
  Labs, and SuperAdmin alike, directly contradicting the stated goal of
  Pharmacy/Labs being genuinely independent, separately-deployable
  services.
- **E is noted as the most elegant long-term answer but deliberately not
  recommended for near-term adoption**, because it requires a new JWT claim
  (`session_epoch` or similar), which — even though arguably identity-layer
  rather than business-layer — is still a change to the frozen contract in
  §9 and should go through the same explicit, dedicated review the thin-token
  decision itself went through, not be adopted as a side effect of a
  readiness report.

## 11. SSO architecture (as it exists today, unchanged by this phase)

Distinguishing four concerns this service and its consumers keep separate,
by design:
- **Authentication** (this service): proving who a credential belongs to —
  `/auth/login`, password verification.
- **SSO / cross-app handoff**: Superadmin's Phase 3/3B integration calls
  this service's issuance endpoints directly (not yet the Phase 3A-style
  opaque-code redeem flow used elsewhere in the platform for Core→Pharmacy/
  Labs — that flow belongs to Core today and was out of scope for this
  phase).
- **Authorization**: entirely local to each consumer (Superadmin's own
  `app/core/auth.py`, unchanged — confirmed in Phase 3's audit it needed
  zero changes to consume Blumax-Auth-issued tokens, since it already
  verified claims structurally rather than trusting a specific issuer
  string beyond config).
- **Application/tenant session**: not this service's concern at all — it
  issues identity, nothing about "which tenant is currently selected,"
  consistent with the thin-token decision.

## 12. User lifecycle architecture

- Blumax Auth owns one `users` table (`id`, `identifier`,
  `hashed_password`, `is_active`) — nothing else.
- Today, the only way to create a user is `scripts/create_dev_user.py`
  (dev-only, direct DB insert, never mints a token itself) — there is no
  production user-provisioning flow yet. This is an explicit, known gap,
  not an oversight: "how a local Superadmin/Pharmacy/Labs/Core user maps to
  a Blumax Auth identity" is a Phase 5/6-scale question (bulk migration or
  dual-write during cutover), correctly out of scope for a DEV/STAGING
  *readiness* phase.
- Superadmin's own user model is untouched (Phase 3 confirmed zero Superadmin
  authorization-code changes) — it continues to resolve its own local user
  by `sub`, regardless of which issuer produced the token verifying that
  `sub`.

## 13. Password migration readiness (restated from Phase 1's MIGRATION.md, unchanged)

`hash_password`/`verify_password_constant_time` use the same passlib/bcrypt
scheme Core uses today (`bcrypt<4.1` pin applies here for the same passlib
1.7.4 compatibility reason). A real migration would copy `hashed_password`
values verbatim — no re-hashing required, since the hash format is
compatible. `verify_password_constant_time` already performs constant-work
verification regardless of whether the identifier exists, closing the
user-enumeration timing side-channel from day one. No code change was made
or needed this phase; this section exists only to confirm the readiness
claim still holds.

## 14. Backup / recovery procedure (DEV/STAGING)

- **Postgres**: `docker exec <postgres container> pg_dump -U authuser
  blumax_auth > backup.sql`; restore via `psql` into a fresh volume.
  Standard Postgres procedure, no Blumax-Auth-specific wrinkle.
- **Redis**: AOF file under `auth_redisdata` is the durable artifact;
  losing it only loses rate-limit counters and in-flight revocation
  markers (§4) — acceptable to recreate empty in a DEV/STAGING disaster
  recovery, not something requiring a dedicated backup job at this scale.
- **Signing key**: back up the `auth_devkeys` volume's
  `auth-jwt-private.pem` (DEV only — staging/production use
  `JWT_PRIVATE_KEY` from secrets management, which is backed up by that
  system, not by this repo). Losing the dev key invalidates every
  outstanding token but is otherwise harmless — it is explicitly never a
  production artifact.
- **Config**: `.env` files are never committed (confirmed — none exists in
  the repo; every `.env` created during this phase's live tests was
  deleted immediately after its test concluded, confirmed above).

## 15. Security review (re-confirmation, no new findings)

Re-checked, no change since Phase 1: constant-time password verification,
RS256-only (no alg=none / HS256-confusion acceptance — unit-tested with
hand-built malicious tokens in `test_jwt.py`), refresh-token rotation with
reuse-detection-revokes-the-family, rate-limited login, explicit
fail-closed session-revocation check (a deliberate, documented departure
from Core's confirmed fail-open behavior — flagged, not silently matched),
no secret logging (§8), non-root container user, production refuses to
start without a real `JWT_PRIVATE_KEY` (§5). No new vulnerability
introduced by this phase's changes (a Dockerfile ownership fix and two
compose volume additions carry no security-relevant behavior change).

## 16. Tests performed

- Full automated suite: **33/33 passed** (final confirmation run this
  phase, from the host virtualenv against temporarily host-exposed
  compose ports, including `test_backward_compat.py`'s live dependency on
  the sibling `blumax_auth` verification package — which is why this run
  could not use the production Docker image directly, since that image
  intentionally excludes `tests/` and dev-only cross-repo dependencies).
- Live persistence drill (ephemeral `p3c-auth` project): bootstrap → real
  login → full container recreation → health/kid/token/login/migration
  checks, all passed (§5).
- Live key-rotation drill (ephemeral `p3c-rotate` project): old key + new
  key coexisting in JWKS, both an old pre-rotation token and a new
  post-rotation token verifying successfully in the same window, all
  passed (§5).
- All disposable Docker infrastructure, `.env` files, and extracted key
  material created for these drills have been torn down and deleted; none
  of it persists on disk or in a running container as of this report.

## 17. Test results summary

| Test | Result |
|---|---|
| 33/33 pytest suite | PASS |
| Container recreation preserves Postgres data | PASS |
| Container recreation preserves Redis data | PASS (AOF) |
| Container recreation preserves signing key (`kid` unchanged) | PASS — the defect this phase fixed |
| Pre-recreation token verifies post-recreation | PASS |
| `alembic upgrade head` idempotent after recreation | PASS |
| JWKS publishes 2 keys during rotation window | PASS |
| Pre-rotation token verifies during overlap window | PASS |
| Post-rotation token verifies during overlap window | PASS |
| `/health` reports granular DB/Redis/key status, real 503 on failure | PASS (code path exercised via unit test; all-healthy path exercised live) |

## 18. Files modified this phase

- `blumax-auth/auth-backend/Dockerfile` — `RUN mkdir -p /app/.dev-keys &&
  chown -R appuser:appgroup /app` (ordering fix so the volume mount point
  has correct ownership before mounting).
- `blumax-auth/auth-backend/docker-compose.yml` — added `auth_devkeys`
  named volume, mounted at `/app/.dev-keys` on the `app` service.
- `blumax-auth/auth-backend/app/api/routes.py` — `/health` now checks DB +
  Redis + signing key individually, returns real 503 on any failure
  (previously only checked DB).
- `blumax-auth/auth-backend/tests/test_jwks.py` — added
  `test_health_reports_all_three_dependencies`.
- `blumax-auth/auth-backend/docs/PHASE3C_DEV_STAGING_READINESS_REPORT.md`
  — this report (new).

## 19. Files explicitly NOT modified

Core, Pharmacy, Labs: zero changes, zero file touches, confirmed by scope
of every edit this phase (all edits were inside
`blumax-auth/auth-backend/`). Superadmin: zero changes this phase (Phase 3/
3B already completed and were not revisited). `blumax-platform` compose/
nginx/deploy files: zero changes. No production `.env`, secret, or key
file anywhere on the host was read, written, or referenced.

## 20. Production impact

**None.** No production service was started, stopped, restarted, or
reconfigured. No production database was connected to. No production
secret was created, read, or rotated. Every container, volume, and
credential used in this phase's live testing was disposable, project-scoped
(`p3c-auth`, `p3c-rotate`, `p3c-final-check`), and has been torn down.
SuperAdmin production remains on `AUTH_PROVIDER=core`, untouched.

## 21. Remaining blockers before SuperAdmin production migration

1. **Real `JWT_PRIVATE_KEY` provisioning for staging/production** — not yet
   generated; must come from a secrets manager, never reused from Core's
   key or from this phase's dev-generated key.
2. **Cross-service logout decision needs a recommendation-to-action
   step** — §10's Option A is a config recommendation, not yet applied to
   any real environment's `ACCESS_TOKEN_EXPIRE_MINUTES` value; Option D is
   designed-but-unbuilt.
3. **No production user-provisioning/migration path exists yet** (§12) —
   required before any real cutover, not before this phase's goal of
   DEV/STAGING readiness.
4. **CORS/trusted-origin configuration** (§7) — needed only once a
   browser-based (not server-to-server) consumer exists.
5. **HTTPS/reverse-proxy wiring at the platform layer** (§7) — a
   `blumax-platform` change, explicitly out of scope for this phase.
6. **`SESSION_REVOCATION_FAIL_MODE` production decision** (§6) — currently
   `closed` here vs. Core's confirmed fail-open; needs an explicit sign-off
   before any production traffic relies on it, since it is a deliberate
   behavioral divergence, not an oversight.
7. **Superadmin's own gap, carried over from Phase 3B**: Superadmin does
   not yet propagate a Blumax-Auth-side logout/revocation, since it has no
   connection to Blumax Auth's Redis — same root issue as §10, unresolved
   by design until a cross-service logout option is actually implemented.

## 22. Exact next-phase recommendation

**Phase 4 should be scoped narrowly**: implement §10's Option A
(short-TTL access tokens) as an actual config change for a named
environment, backed by a stated logout-latency requirement from the user —
not inferred unilaterally — since Phase 3C's own charter reserves that
decision. In parallel, Phase 4 should produce the real
production-signing-key provisioning runbook (§21.1) and the explicit
`SESSION_REVOCATION_FAIL_MODE` production decision (§21.6), since both are
pure decision/documentation work with no code risk, matching this
engagement's established pattern of separating decision phases from
migration phases. Migrating Core, Pharmacy, or Labs remains explicitly
out of scope until SuperAdmin has run on Blumax Auth in a real
staging/production environment for a defined stable period — consistent
with the target architecture's own stated sequencing
(`BLUMAX AUTH → {SUPERADMIN, CORE, PHARMACY→LABS}`).

---

**Confirmation**: all live Docker infrastructure created during this phase
(`p3c-auth`, `p3c-rotate`, `p3c-final-check` — containers, networks, and
named volumes) has been torn down. All `.env` files and extracted key
material created for testing have been deleted. No commit was made and
none will be made without an explicit, separate request.
