# PHASE 4G-0 — PRODUCTION CUTOVER READINESS AUDIT REPORT

This is a READINESS AUDIT ONLY. No production migration was performed, no
production user/database/Redis/signing-key/DNS was touched, nothing was
deployed, committed, or pushed. All claims below are verified against the
actual repositories on disk (file:line citations throughout), not against
prior reports' claims.

## 1. Executive summary

Blumax Auth's identity/JWT/key-rotation/Redis design is sound and already
live-proven in DEV across Phases 4D–4F (identity continuity, SSO, password
delegation, hardened migration tooling). **But the service has never been
introduced into the production deployment topology at all** — no compose
entry, no database, no Redis allocation, no secrets, no nginx route, and
Labs' own production env template (`labs.env.example`) has no
`AUTH_PROVIDER`/`BLUMAX_AUTH_API_URL`/`JWKS_URL` variables to even point at
it. Layered on top of that: the long-standing facility-scope gap becomes a
real tenant-data-exposure risk for any facility-restricted org under this
provider, and the hardened migration tool — while fully tested against
synthetic data — has never been run against a real Core production export.
None of these are open-ended unknowns; each has a concrete, scoped fix.

## 2. Final verdict

# BLOCKED

Blocked specifically because: (a) attempting Phase 4G-1 today would mean
switching `AUTH_PROVIDER` to a service with no production deployment,
which is a production authentication outage by definition; (b) the
facility-scope gap can expose one facility's data to a user restricted to
another, for any org that uses facility restriction; (c) the migration
tool has only ever processed synthetic data, never a real Core export,
so its invariants are proven in design but not yet proven against
production data's actual shape. Each blocker below has a named,
achievable remediation — this is a "not yet wired up" verdict, not a
design-flaw verdict.

## 3. Repositories inspected

`blumax-auth` (auth-backend), `blumax-labs` (labs-backend, labs-frontend,
labs-admin-portal-frontend), `blumax-backend` (Core, for comparison only —
not modified), `blumax-platform` (compose files, nginx, docs, scripts).
`blumax-pharm` and `blumax-superadmin` were checked for git-safety only
(Step 1), not substantively audited — this phase is scoped to Labs.

## 4. Git status before/after

| Repo | Branch | Before | After |
|---|---|---|---|
| blumax-auth | dev | `?? auth-backend/` (pre-existing, whole repo never committed) | unchanged except this report added under `docs/` |
| blumax-labs | dev | 6 modified + 3 untracked (Phase 4A–4F work, pre-existing) | **unchanged** — no file touched this phase |
| blumax-pharm | dev | clean | unchanged |
| blumax-superadmin | dev | 1 modified + 2 untracked (pre-existing Phase 3 work) | unchanged |
| blumax-platform | main | clean | unchanged |
| blumax-backend | dev | 15 modified + 11 untracked (pre-existing, unrelated tenant-sync work in progress) | unchanged — not touched, noted but out of scope |

No commit, push, or discard of any existing work occurred.

## 5. Blumax Auth production readiness

Verified directly against code (full citations from the dedicated audit
agent, cross-checked):

- **Identity**: `users` (UUID PK, unique `identifier`, NOT NULL
  `hashed_password`/`is_active`) + `refresh_tokens` (UUID PK, FK→users
  CASCADE, `revoked` flag, `expires_at`, no token value stored — the
  row's own id is the refresh `jti`). Sound, minimal, matches the design
  intent.
- **JWT**: RS256; `kid` = first 16 hex of SHA-256 of the public key's DER
  SPKI (deterministic, not random); `iss`/`aud` from settings, checked on
  decode; `type` claim (`access`/`refresh`/`service`) enforced via a
  mandatory `expected_type` param, not optional; `jti` present on every
  token type; expiries: access 15 min, refresh 14 days, service 10 min.
- **Key rotation**: production refuses to start without a real
  `JWT_PRIVATE_KEY` (`keys.py`'s production guard, confirmed real). Dual-key
  overlap via `JWT_PREVIOUS_PUBLIC_KEY`, both `kid`s published in JWKS,
  live-drilled in `docs/PHASE3C_DEV_STAGING_READINESS_REPORT.md`. Old-key
  removal is **manual only** (drop the env var, redeploy) — no auto-expiry.
  **Real risk is operational, not coded**: `signing_keys()` is
  `@lru_cache`'d per-process, so a multi-instance rollout that updates
  `JWT_PRIVATE_KEY` without `JWT_PREVIOUS_PUBLIC_KEY` in the *same* deploy
  step would invalidate in-flight tokens — nothing in code prevents this
  misordering; it must be a disciplined runbook step.
- **Redis**: four uses — session revocation, SSO codes, password-reset
  codes (all **fail-closed**, confirmed in code, not just by config
  default) — and login rate-limiting, which **fails open** (no try/except
  around the Redis call), a deliberate, documented asymmetry worth
  surfacing explicitly in any sign-off: on a Redis outage, revocation/SSO/
  reset become unusable (safe direction) while rate-limiting silently
  disappears (unsafe direction, but consistent with the service's own
  stated posture).
- **Database isolation**: confirmed, no Core/Labs DSN or cross-reference
  anywhere in the repo; the migration script's `--source-db-url` flag is
  unwired/unused, not a live cross-DB connection.
- **Secrets/production config — the central finding**: **no production
  compose file, no `.env.prod`, no production secrets template exists in
  this repo at all.** `docker-compose.yml` self-labels "Local development
  ONLY... not wired into dev-infra or blumax-platform." `.env.example` is
  explicitly dev-only, with placeholder issuer (`https://auth.blumax.health`
  — not a confirmed-live domain) and empty `JWT_PRIVATE_KEY`.
- **Docs divergence**: `MIGRATION.md` still describes a Phase-1-only
  service and lists service-tokens as "not built," while the actual code
  already has service accounts, SSO, and password reset (Phase 5) — a
  genuine doc/code gap for anyone using MIGRATION.md as the status source.

## 6. Identity migration readiness

The Phase 4F-hardened `scripts/migrate_core_user.py` supports every
required capability: stable UUID preservation, preflight duplicate
detection (by id and by normalized identifier, before any DB write),
per-row malformed-UUID isolation, documented trim+lowercase-only
normalization, email-conflict detection, orphan detection against an
operator-supplied Labs `core_user_id` list, idempotent reruns, per-row
transaction safety (one bad row never aborts the batch), and a full
category-count report with a clean/non-clean exit code. All proven live
in DEV against synthetic datasets up to 168 rows (Phase 4F) and a 70-user
anomaly-rich dataset (Phase 4E).

**Gap**: this tool has never been run against a real export of Core's
actual production `users`/tenant-membership data. Core's export format,
volume, and any real-world anomaly it contains (beyond the synthetic ones
already tested) remain unverified. No production Core database was
accessed to check this, per this phase's explicit constraint — this is
recorded as an untested step, not resolved by assumption.

The mapping chain `Core identity id → Blumax Auth users.id → Labs
LabUser.core_user_id` is one-to-one and deterministic by construction:
the migration tool only ever inserts a row under the Core-supplied id
verbatim (never remaps it), and `LabUser.core_user_id` is a free-form
opaque string column with no semantic dependency on which service issued
the UUID (Section 7).

## 7. Password migration readiness

Confirmed byte-for-byte: both Core (`blumax-backend/app/core/security.py`)
and Blumax Auth (`auth-backend/app/core/security.py`) use
`passlib.context.CryptContext(schemes=["bcrypt"], deprecated="auto")`
with no cost-factor override in either — bcrypt's format self-describes
its own cost per hash, so a Core-produced hash verifies unchanged under
Blumax Auth's verifier with zero re-hashing. Core's `hashed_password`
column is `String(255) NOT NULL` — structurally no passwordless/alternate-
auth user population exists in Core's own schema (no OTP/magic-link
column found anywhere in the identity module).

**Classification: 100% of Core's user population is directly migratable**,
pending the real-export caveat in Section 6. No forced password reset is
required or was performed. If a future real export reveals any row with a
non-bcrypt or malformed hash, that is a per-row `error`/`invalid`
classification the hardened tool already handles safely (reported, not
silently dropped or reset).

## 8. Labs identity-link readiness

`LabUser.core_user_id` (`labs-backend/app/models/lab_user.py:47`):
`String(64)`, nullable, **unique**, indexed. This can safely hold either a
Core-issued or a Blumax-Auth-issued UUID string — it has no FK, no format
assumption beyond "a string," and the migration design's identity-
continuity guarantee (same UUID, same column, same semantics) means this
column requires **zero schema change**.

Searched the full Labs backend for `core_user_id`, `decode_core_token`,
Core JWT issuer/JWKS, Core login, Core SSO, Core auth endpoints. Every
occurrence falls into one of:

1. **Authentication** — `app/core/security.py::decode_core_token`
   (provider-aware since Phase 4A, verifies whichever issuer
   `AUTH_PROVIDER` points at), `app/core/config.py`'s `AUTH_PROVIDER`/
   `jwks_url`/`JWT_ISSUER`/`JWT_AUDIENCE` computed properties,
   `app/services/core_login.py` (password delegation).
2. **Business integration** — directory sync, lab-order consumption,
   result relay, billing sync, DIS attachments (Section 13) — never
   touches identity/auth.
3. **Identity mapping** — `LabUser.core_user_id` itself, and
   `app/api/v1/deps.py`'s lookup of a `LabUser` by that column.
4. **SSO** — `app/core_client.py`'s redeem/mint-on-behalf functions,
   already AUTH_PROVIDER-branched since the "NEXT PHASE" work.
5. **Unrelated legacy code** — none found; every Core reference serves one
   of the four categories above.

Nothing was removed or renamed. No code anywhere assumes Core-specific
identity semantics beyond "a UUID string, opaque" — this was the
intentional design and it holds up under this fresh search.

## 9. AUTH_PROVIDER / issuer readiness

`AUTH_PROVIDER: Literal["core", "blumax_auth"] = "core"`
(`labs-backend/app/core/config.py:55`) is a **single exclusive value, not
a dual-issuer mechanism**. Switching it is configuration-only (no code
deploy) and rollback is equally configuration-only (flip the env var
back, restart) — confirmed, this part of the prior claim holds.

**But Labs cannot accept Core-issued and Blumax-Auth-issued tokens
simultaneously.** There is no dual-issuer support in the code at all — a
genuinely important finding for Section 19. Explicitly, at the moment of
a flip:

- Any already-presented Core-issued **external** bearer token (the
  `decode_core_token` path in `deps.py`) immediately fails issuer/audience
  verification against the now-active Blumax Auth JWKS → 401 on next call.
- Refresh tokens: Labs never stores a Core/Blumax-Auth refresh token for
  its own session management (Section 11) — not a factor.
- Browser sessions from Labs' **own** `/auth/login` are unaffected by the
  flip at all (Section 11) — this significantly narrows the blast radius
  from "a hard cutover breaks every session" to "a hard cutover breaks
  only externally-token-bearing (SSO-launched) sessions."

A hard cutover is therefore required only for the SSO-launched-session
population, and production also lacks the env-var plumbing to even make
this switch today (Section 16) — this is a planning item for Phase 4G-1,
not something this phase needed to build.

## 10. Login flow readiness

Traced end-to-end. Both Labs frontends (`labs-frontend`,
`labs-admin-portal-frontend` — see Section 18 for the "2 frontends" claim
correction) call **Labs' own backend** (`POST /api/v1/auth/login` or
`POST /auth/login` respectively), never Core or Blumax Auth directly from
the browser. `labs-frontend` additionally has an SSO code-redemption path
(`?sso=<code>&tenant=<id>` → `POST /api/v1/auth/sso/redeem`) and a
same-origin cookie-refresh path proxied through nginx straight to Core
(`/auth/refresh` → Caddy/nginx → `core:8000`) — this second path is an
**infra-level Core assumption living in nginx config, not in Labs' own
code**, and must be repointed at Blumax Auth as part of cutover (Section
27). Neither frontend decodes a JWT client-side; both use a backend
`/auth/me`-style call for role/UI info, so Blumax Auth's deliberately thin
JWT (no role/tenant/facility claims) does not break either UI — a
meaningful de-risking finding.

**Exact changes required for production** (not made in this phase):
(1) add `AUTH_PROVIDER`/`BLUMAX_AUTH_API_URL`/`BLUMAX_AUTH_JWT_ISSUER`/
`BLUMAX_AUTH_JWT_AUDIENCE` to `labs.env`; (2) repoint the nginx
`/auth/refresh` proxy target for the SSO cookie-refresh path.

## 11. Password-delegation assessment

`core_login.py::verify_core_password` is already `_login_target()`-
branched by `AUTH_PROVIDER` (built in the "NEXT PHASE" work, unchanged
since). Critically — newly confirmed this phase — **`/auth/login`'s own
handler always mints a local Labs HS256 token (`_mint()`,
`app/api/v1/auth.py:107-119`) for the browser, regardless of which
provider checked the password.** The identity-provider token obtained
during the check is used only momentarily and explicitly logged out
afterward ("the session this check created is still ended afterward").

Answering the four required questions:
1. **Which users depend on it?** Every `LabUser` with `core_user_id` set
   and `password_hash` NULL (Core-provisioned staff with no local Labs
   password) — Category B/Category "core_linked_no_password" from the
   Phase 4E dataset design, a real and non-trivial population in
   production.
2. **Can they migrate to Blumax Auth password auth?** Yes — Section 7
   confirms their Core bcrypt hash verifies unchanged under Blumax Auth.
3. **Can the path be removed after migration?** The *Core-pointed* branch
   can eventually be deleted once `AUTH_PROVIDER=blumax_auth` is the
   permanent production setting and a stable observation period has
   passed (same D-category disposal pattern as Blumax Auth's own dormant
   issuance code) — not before.
4. **Any population locked out if it disappeared prematurely?** Yes —
   every Core-linked, Labs-passwordless user would lose their only login
   path if this were removed before the migration completes. `replace_
   temporary_password` is explicitly NOT provider-branched (hardcoded to
   Core) because Blumax Auth has no temporary-password concept at all —
   confirmed still correct; this function simply becomes unreachable
   dead code under `AUTH_PROVIDER=blumax_auth`, not a bug.

## 12. SSO assessment

Blumax Auth exposes `POST /auth/sso/code`, `/code/on-behalf`, `/exchange`,
and (newly confirmed this phase) `/code/consume` (`app/api/
sso_routes.py:19-72`) — a complete SSO authority, already proven live
against Labs in Phases "NEXT PHASE"/4D/4E. Today, **Core** is the SSO
authority (mints/redeems); Blumax Auth can structurally take over the
same role (`core_client.py`'s `AUTH_PROVIDER`-gated branches already call
the Blumax Auth equivalents). Business-data API calls (patient/provider
directory, result relay, billing, DIS) are cleanly separate from this —
none of them route through SSO code exchange, confirmed in Section 13.
No SSO endpoint was changed in this phase.

## 13. Logout/revocation assessment

Confirmed by direct grep: **zero** revocation-checking code exists
anywhere in Labs (`revocation`/`is_revoked`/`session_revok`/`jti` — no
hits in `app/`). `decode_core_token` performs pure stateless JWT
verification via the shared `blumax_auth.TokenVerifier` library — it
never queries Blumax Auth's Redis-backed revocation marker. This is
**unchanged behavior from today's Core-token verification** (Core
tokens are verified the same stateless way already) — not a regression
introduced by this migration, a pre-existing architectural choice.

1. After Blumax Auth logout: the issued access token remains valid until
   its own expiry (15 min) from Labs' point of view.
2. Labs does **not** immediately reject it.
3. No revocation checking exists.
4. Labs caches JWKS only (via `blumax_auth.jwks_cache()`).
5. Maximum externally-issued access-token lifetime: 15 min (Blumax Auth)
   / 10 min (Core today) — bounds the exposure window.
6. Immediate global logout is not currently required for Labs' own local
   sessions (which never carry an external token at all, Section 11) —
   only for the narrower SSO-launched-session population.

**Classification: acceptable by design for native Labs sessions;
requires a documented limitation (not new implementation) for
SSO-launched sessions** — this mirrors the already-known SuperAdmin Phase
3B finding, not a new problem this migration introduces.

## 14. Labs RBAC verification

Confirmed local and independent: `app/api/v1/deps.py::require_role`
checks only `CurrentUser.role` (resolved from `LabUser.role_ref.name`,
itself resolved from the DB by `lab_user_id`/`core_user_id` lookup) and
the local `is_super_admin` flag — **never** a tenant, role, facility, or
permission JWT claim of any kind, confirmed by the same deps.py read that
grounds Section 9/13. `Role` model: `is_system`/`is_locked` flags mark 5
seeded system roles (admin, doctor, supervisor, technologist,
receptionist); custom roles are organization-scoped, created via
`create_custom_role`, with name validation against the system-role names
list. No redesign performed or needed — this phase only verified the
existing model holds.

## 15. Facility-scope assessment

Reconfirmed (not fixed) at `app/api/v1/deps.py:52-79`. The
external-token branch (any Core- or Blumax-Auth-issued bearer token)
never reads `LabUserFacility` — `facility_ids` stays `[]` and falls
through to "every active facility in the organization," because Blumax
Auth's (and Core's) JWT deliberately carries no facility claim. The
**native**-token branch (Labs' own login) correctly resolves facility
scope via `_resolved_facility_ids`.

- **Affected path**: exactly the external-token branch of
  `get_current_user`.
- **Exists in production today?** Yes — this is Core-token behavior
  today too, unchanged by this migration; it is not introduced by the
  cutover.
- **All users or only restricted-facility users?** Only users who arrive
  via an external token AND whose org actually restricts some staff to a
  facility subset. Unrestricted orgs are unaffected (the fallback gives
  them nothing they weren't already entitled to).
- **Caused by the migration?** No — pre-existing, orthogonal.
- **Can a user access another facility's data?** Yes, for a
  facility-restricted user who authenticates via an external token:
  report-listing/history endpoints (`app/api/v1/report.py`) pass
  `facility_scope(current)` straight through to the service layer, which
  would include every facility in the org, not just their assigned one.
- **Fixable independently?** Yes — it needs a `LabUser.id`-keyed facility
  lookup added to the external-token branch, independent of any token
  claim, unrelated to identity migration.

**Classification: BLOCKER for production cutover of any org that uses
facility restriction** (non-blocker for orgs that don't). Recommend a
dedicated, separately-scoped fix phase before Phase 4G-1 proceeds for any
such org.

## 16. Core business dependency classification

Confirmed via dedicated inventory (file:line citations from the audit
agent). All of the following are BUSINESS DATA, EVENT BUS, or
PROVISIONING — **none are authentication** — and none change under this
migration:

| Mechanism | Classification |
|---|---|
| Patient/provider directory sync (pull) | BUSINESS DATA |
| Lab order event consumption (raw Redis stream read, `lab_order_consumer.py`) | EVENT BUS |
| IPD investigation-order push (inbound, shared-key) | BUSINESS DATA |
| Finalized result relay → Core `lab_imaging` + IPD result-ready callback | BUSINESS DATA |
| Tenant/facility/role provisioning relays (both directions) | PROVISIONING |
| OPD↔Labs billing sync, Labs→Billing charge worker | BUSINESS DATA |
| DIS attachment outbox | BUSINESS DATA |
| `blumax:events:lab`, `blumax:events:tenant_module` Redis streams | EVENT BUS |

One pre-existing, orthogonal design note reconfirmed: `lab_order_
consumer.py` reads Core's raw Redis stream directly rather than through
an HTTP relay — unrelated to auth, not addressed here.

## 17. Service-to-service authentication assessment

From the credential inventory: `core_service_client_id/secret`
(directory-sync), `core_report_relay_client_id/secret`,
`core_role_sync_client_id/secret`, `core_labs_documents_client_id/secret`
are all SERVICE AUTHENTICATION used exclusively to reach **Core's business
APIs** — these stay pointed at Core, unaffected by the auth migration.
`hms_service_api_key`, `ipd_callback_service_key`,
`opd_lab_billing_service_key`, `billing_service_key`,
`core_provisioning_service_key` are BUSINESS AUTHORIZATION (shared keys
gating a specific capability, not proving a human's identity) — all
IPD/OPD/Billing/provisioning-facing, unrelated to Core as an auth
provider, unaffected. The one AUTH-ONLY pair,
`blumax_auth_sso_service_client_id/secret` (`config.py:95-96`), already
exists, confirmed distinct from every business-facing credential, and is
used exclusively by the `AUTH_PROVIDER=blumax_auth` SSO/service-token
branches. No credential was replaced or rotated in this phase.

## 18. Frontend readiness

**Correction to this engagement's own service table**: the Labs module
has two frontends, `labs-frontend` (TanStack, the actual lab-operations
staff app — reception/samples/results/QC/catalog/inventory) and
`labs-admin-portal-frontend` (Vite/React, a platform-team tenant/
super-admin console) — **neither is patient-facing**. No patient-portal
codebase exists anywhere under `/home/BluMax_Health`. This is a
documentation mismatch in the platform's own service table, not a
blocker, but worth correcting.

- `labs-frontend`: localStorage token storage, a working refresh-retry
  interceptor, an SSO redeem path, a cookie-based same-origin Core-refresh
  fallback (the nginx dependency flagged in Section 10), and a global
  401→redirect-to-login handler. No client-side JWT decoding (uses
  `/auth/me`). Low risk.
- `labs-admin-portal-frontend`: localStorage token, **no refresh logic at
  all**, **no global 401 handler** (a 401 mid-session surfaces as a local
  per-call error, not a forced logout) — a pre-existing UX gap, not an
  issuer-migration-specific risk, but worth fixing given its low
  production footprint (Section 20: this frontend has no deployed
  service entry at all today).

**Exact changes required**: repoint `labs-frontend`'s API base URL env
var and the nginx `/auth/refresh` proxy target; no code change appears
necessary in either frontend for the issuer switch itself, since neither
hard-codes Core's issuer/audience.

## 19. Production deployment architecture

The single most important finding of this audit:

- **Blumax Auth has no service entry in any production compose file.**
  Every "blumax-auth" reference in `docker-compose.prod.yml` is a
  Docker build-time context (`additional_contexts`) so other services can
  `COPY --from=blumax-auth/...` the shared verification library — there
  is no `blumax-auth:`/`auth-backend:` service key, no image, no port, no
  env block, no database, no Redis allocation, anywhere.
- Labs itself (`labs`, `labs-migrate`, `labs-order-consumer`,
  `labs-billing-charge-worker`, `labs-frontend`) is fully deployed with
  its own least-privilege Postgres role and a shared Redis instance under
  its own logical DB index (`redis://...@redis:6379/4`).
  `labs-admin-portal-frontend` has **no service entry at all** — unbuilt/
  undeployed in production today.
- `labs.env.example` has **no** `AUTH_PROVIDER`, `BLUMAX_AUTH_API_URL`, or
  `JWKS_URL` variable — only `CORE_API_URL`/`JWT_ISSUER`/`JWT_AUDIENCE`/
  `CORE_SERVICE_CLIENT_ID`/`CORE_PROVISIONING_SERVICE_KEY` exist today.
- nginx has routes for `labs.blumaxhealth.com` and `api.blumaxhealth.com`,
  both explicitly treating Core as the sole token issuer (`/auth/` →
  `core:8000`, `/.well-known/` → `core:8000` for JWKS) — **no
  `auth.blumaxhealth.com` or any Blumax Auth route exists.**
- No Labs healthcheck block exists in the compose file (contrast with
  Core, which has one) — a pre-existing gap, not introduced here.
- `docs/DEPLOYMENT_CONTRACT.md`/`ENVIRONMENT_CONTRACT.md`/`RELEASE_
  PROCEDURE.md` have zero mentions of Blumax Auth and no documented
  procedure for onboarding a new backend service into production at all.

## 20. Observability requirements

`scripts/check-health.sh` already checks Labs at three layers (ingress/
TLS, application `/health`, and a billing-outbox backlog metric) — adding
Blumax Auth would need equivalent entries at all three layers, plus a new
backlog baseline if one is ever needed. **No metrics/logging/alerting
infrastructure exists in the deployed stack at all** —
`docs/SHIPPING_BLUMAX.md` explicitly documents capped json-file logs
across 76 containers with no aggregation, and lists Loki/Grafana/Sentry as
a *future, unbuilt* Month-2-3 item. Login/refresh/401/403/unknown-identity
rates for Blumax Auth would need to be built from nothing — there is no
existing dashboard to extend.

**Minimum required before cutover** (from this audit, not yet built):
login success/failure rate, refresh success/failure rate, 401 rate, 403
rate, missing-LabUser-link count (a Blumax-Auth-verified token whose `sub`
has no matching `LabUser.core_user_id`), password-migration-script error
count, JWKS/Blumax-Auth/Redis/database availability. **No numeric
threshold is defined anywhere in the existing system for any of these** —
every threshold is an operational decision still to be made, not
something this audit can responsibly invent.

## 21. Rollback strategy

Config-only in principle (`AUTH_PROVIDER=core`, restart Labs) — but this
is untested in production because production cannot currently run
`AUTH_PROVIDER=blumax_auth` at all (Section 19). Rollback triggers (none
have a pre-existing numeric baseline in this system, all require an
operational decision): authentication failure rate exceeding baseline,
any migrated user unable to log in, an identity-mapping mismatch
surfacing in logs, SSO failure, an unexpected authorization change
(should be impossible given Section 14's local-RBAC confirmation, but
worth monitoring anyway), a facility-isolation incident (Section 15),
refresh-token failure, or Blumax Auth instability of any kind.

## 22. Session-transition strategy

The safest strategy, given Section 9/11's findings: **native Labs-login
sessions are entirely unaffected by the flip** (they always carry a
locally-minted HS256 token, independent of which provider checked the
password) — only **externally-token-bearing (SSO-launched) sessions**
break, and they self-heal: Core's/Blumax Auth's short access-token
lifetime (10-15 min) means any such session either naturally re-requests
a token from whichever provider is now active, or hits a 401 and the
frontend's existing redirect-to-login/re-SSO flow recovers it, within
minutes, with no manual intervention. Core refresh tokens are never
held by Labs itself (Section 11), so there is no stranded-refresh-token
cleanup needed on Labs' side. Recommend flipping `AUTH_PROVIDER` during
a low-traffic window regardless, purely to minimize the number of
SSO-launched sessions that have to self-heal at once, not because
anything would be lost.

## 23. Security assessment

No token/issuer/audience/algorithm confusion risk found: `decode_core_
token` validates issuer, audience, and signature via the shared
`blumax_auth.TokenVerifier` library regardless of which provider is
active, and `AUTH_PROVIDER` only ever selects one pair of trust-anchor
values at a time (Section 9) — there is no mode where both are
simultaneously trusted, so a Core-issued token can never be mistaken for
a Blumax-Auth-issued one or vice versa. No identity substitution/duplicate-
identity risk: the migration tool's preflight duplicate/conflict detection
(Phase 4F) prevents this at the data layer, and `LabUser.core_user_id`'s
unique index prevents it at the Labs schema layer. No JIT-provisioning
risk: Labs still requires a pre-existing `LabUser.core_user_id` link for
any external-token login — confirmed unchanged (`deps.py:62-67`'s explicit
403, not JIT-create). No privilege escalation or stale-authorization risk:
RBAC is entirely local (Section 14), untouched by which provider issued
the token. No password disclosure: the migration tool never logs a
hash value (Phase 4F security review, reconfirmed). Refresh-token reuse:
unaffected, Labs' own refresh tokens are entirely local and provider-
independent. **The one confirmed exposure is the facility-scope gap**
(Section 15) — a genuine cross-facility data-access risk, independent of
and not introduced by this migration, but real for any affected org.

**Required-access invariant confirmed**: `valid Blumax Auth token` (or
Core token, per whichever provider is active) **+** `valid LabUser
mapping` (`deps.py:59-67`) **+** `valid Labs role` (`require_role`) is
already enforced as a conjunction, not an either/or, for every protected
Labs endpoint.

## 24. Exact blockers

1. **Blumax Auth does not exist in production deployment topology at
   all** — no compose service, database, Redis, secrets, or nginx route.
2. **`labs.env.example` has no `AUTH_PROVIDER`/`BLUMAX_AUTH_API_URL`/
   `JWKS_URL` variables** — the toggle this whole design depends on isn't
   even wired into the production env template yet.
3. **Facility-scope gap** — a real cross-facility data-exposure risk for
   any org using facility restriction, under either provider, but
   specifically relevant here because cutover is the forcing function to
   finally address it.
4. **The hardened migration tool has never processed a real Core
   production export** — only synthetic data to date.

## 25. Exact conditions

1. A dedicated facility-scope fix phase, completed and deployed, **before**
   Phase 4G-1 proceeds for any org that uses facility restriction.
2. A real (even if partial/sampled) Core export run through the Phase 4F
   tool in dry-run mode, with its report reviewed by an operator, before
   `--execute` is ever pointed at production data.
3. A documented, rehearsed rollback runbook (config flip + restart),
   tested in a staging-equivalent environment at least once, since it has
   never been exercised against a real deployment.
4. At minimum the metrics listed in Section 20 wired into
   `check-health.sh` or an equivalent, with operator-chosen thresholds,
   before cutover — not full Loki/Grafana/Sentry, but something beyond
   "no visibility at all."
5. `MIGRATION.md` brought up to date, or explicitly superseded by the
   Phase docs, so there is one trustworthy status source (minor, not a
   hard blocker, but confusion-prone otherwise).

## 26. Exact changes required before 4G-1

- Add a `blumax-auth` service (image, ports or internal-only networking,
  its own Postgres + Redis, health check) to `docker-compose.prod.yml`.
- Add `AUTH_PROVIDER`, `BLUMAX_AUTH_API_URL`, `BLUMAX_AUTH_JWT_ISSUER`,
  `BLUMAX_AUTH_JWT_AUDIENCE`, and the service-credential pairs
  (`blumax_auth_sso_service_client_id/secret` already named in Labs'
  code) to `labs.env`.
- Decide and provision real production `JWT_ISSUER`/`JWT_AUDIENCE` values
  for Blumax Auth (the current `.env.example` values are Phase-1
  placeholders).
- Add an nginx route if Blumax Auth needs any direct external exposure
  (JWKS fetch can stay internal-network-only if Labs reaches it via
  Docker service DNS — confirm this design choice explicitly rather than
  defaulting to "needs public DNS").
- Repoint `labs-frontend`'s nginx-proxied `/auth/refresh` cookie-refresh
  target from `core:8000` to the new Blumax Auth service.
- Fix the facility-scope gap (Section 15).
- Wire minimum observability (Section 20/25).
- None of the above were implemented in this phase, per its own
  read-only scope.

## 27. Proposed production cutover sequence (proposed only, not executed)

1. Production readiness confirmation — re-run this audit's blockers list,
   confirm all closed.
2. Backup/export — a full, real Core identity export, taken read-only.
3. Identity migration — `migrate_core_user.py --execute` against the real
   export, reviewed dry-run first (**requires**: backend deployment of
   Blumax Auth to production; **requires**: database migration target
   exists).
4. Validation — row-count and spot-check verification (no restart needed).
5. Blumax Auth availability verification — health check, JWKS reachable
   from Labs' network (no restart needed, pure verification).
6. Labs configuration preparation — stage `AUTH_PROVIDER=blumax_auth` and
   related env vars, not yet applied (**requires**: configuration
   reload/restart when applied in the next step).
7. Controlled authentication switch — apply the staged config,
   **requires backend restart** of the Labs service (not full downtime if
   rolled instance-by-instance, but a restart nonetheless).
8. Smoke testing — native login, SSO-launched login, password-delegated
   login, refresh, logout, each exercised live.
9. Monitoring window — watch the Section 20 metrics at whatever cadence
   the operator decides.
10. Rollback criteria — as listed in Section 21, continuously evaluated
    during the window.
11. Rollback procedure — `AUTH_PROVIDER=core`, restart Labs
    (**requires**: backend restart, no database change needed since Core's
    own identity rows are untouched by this migration).
12. Stabilization — extended observation at normal traffic.
13. Eventual Core-auth removal — only after a defined stable period with
    zero fallback invocations, mirroring Blumax Auth's own "Category D"
    dormant-code disposal pattern; **requires** a deliberate, separate,
    later decision — not part of this sequence's near-term scope.

Steps 3, 6→7, and 11 are the only ones requiring a backend
restart/configuration reload; none require a frontend deployment or a DNS
change under the current design (where Blumax Auth stays internal-
network-only) — a DNS change becomes necessary only if that design
decision changes (Section 26).

## 28. Proposed rollback sequence

1. Set `AUTH_PROVIDER=core` in Labs' environment.
2. Restart the Labs backend service (`labs`) only — no other service,
   frontend, or database is touched.
3. Confirm JWKS/issuer/audience reverted via a live login smoke test.
4. Confirm native-login sessions were never disrupted (Section 22) and
   SSO-launched sessions re-acquire a Core-issued token on their next
   natural refresh/401 cycle.
5. No data rollback is needed — the migration only ever inserts new
   Blumax Auth rows; it never deletes or mutates Core's own data, so
   reverting the provider toggle fully restores the pre-cutover behavior
   without a database restore.

## 29. What was NOT changed

No file in `blumax-labs`, `blumax-pharm`, `blumax-superadmin`,
`blumax-backend`, or `blumax-platform` was modified. No production user,
database, Redis instance, signing key, DNS record, or compose/env file
was touched. No `AUTH_PROVIDER` value was switched anywhere. No Core
authentication path was removed or disabled. No session was invalidated.
No credential was rotated. The only artifact produced by this phase is
this report file, added under `blumax-auth/auth-backend/docs/`.

## 30. Confirmation that no production system was modified

Confirmed by the Section 4 git-status comparison (byte-identical before
and after across every repo except this report's own addition) and by
this phase's exclusive use of direct, read-only code inspection plus
four read-only research agents — no docker command, database write,
Redis write, deployment script, or git write-operation (commit/push) was
executed against any production-pointed target at any point in this
phase.

---

Per this phase's own governing instruction: **Phase 4G-1 is not started.**
This audit stops here, with the verdict **BLOCKED** on the four items in
Section 24, each with a named, scoped remediation in Sections 25-26 —
not an open-ended architectural problem.
