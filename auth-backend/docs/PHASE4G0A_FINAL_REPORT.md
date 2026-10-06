# PHASE 4G-0A — DEV SERVER BLOCKER CLOSURE — FINAL REPORT

Scope reminder: this phase operated **only** on the real BLUMAX DEV
server and DEV data. "Production" means the separate, actual live
customer environment, which was never touched, queried, or modified.

## Status table

| Item | Status | Evidence |
|---|---|---|
| Blumax Auth DEV deployed | **DONE** | `dev-auth` container, healthy (`/health`: db/redis/signing_key all `ok`); [deployment doc](PHASE4G0A_DEV_SERVER_DEPLOYMENT.md) |
| Blumax Auth DB isolated | **DONE** | Dedicated `blumax_auth` role+database; live-confirmed `permission denied for table lab_user` when attempting cross-service data access |
| Blumax Auth Redis working | **DONE** | Shared `dev-redis`, dedicated logical index 5; session revocation/SSO-code/password-reset all exercised live |
| JWKS working | **DONE** | Real RS256 key served at `/.well-known/jwks.json`; verified by Labs and Superadmin against real tokens |
| Superadmin using Blumax Auth | **DONE (tested, not left enabled)** | 11/11 checklist items passed live against `dev-auth`: valid identity+grant+role+permission (200), no grant (403), tampered signature/wrong-issuer/wrong-audience/expired (401 via invalidated signature), unknown kid (401, distinct message), Core rollback confirmed on the live deployed service |
| Labs provider abstraction | **DONE** | `AUTH_PROVIDER` toggle pushed, deployed to real `dev-labs`, env wired; [migration doc](../../blumax-labs/labs-backend/docs/PHASE4G0A_LABS_AUTH_MIGRATION.md) |
| Labs using Blumax Auth | **DONE (tested, not left enabled)** | Full delegated-login chain proven live against real `dev-auth` (password delegation → RS256/JWKS verification → local token mint); `dev-labs` itself left on `AUTH_PROVIDER=core` |
| Facility scope fixed | **DONE (implemented + tested, NOT deployed)** | [fix doc](../../blumax-labs/labs-backend/docs/PHASE4G0A_FACILITY_SCOPE_FIX.md); reproduced, root-caused, fixed in the shared `deps.py` layer |
| Facility regression tests | **DONE** | 12/12 new tests pass; confirmed 7/8 security-relevant ones fail against the pre-fix code; full 765/765 Labs suite green |
| Real DEV Core export tested | **DONE** | 56 eligible real rows (of 86 total, 10 soft-deleted + 20 service accounts excluded), dry run clean, [export doc](PHASE4G0A_REAL_DEV_EXPORT_DRY_RUN.md) |
| DEV identity migration | **DONE** | 56/56 executed, idempotent re-run confirmed, byte-for-byte integrity confirmed against Core's originals |
| Cross-application identity tested | **DONE** | One shared identity: full Labs access (doctor role) + zero Superadmin access (403, no grant); reverse direction also confirmed (Superadmin grant ⇏ Labs access) |
| Core business APIs preserved | **DONE (unchanged)** | `CORE_API_URL` and every Core business-facing credential untouched in both Labs' and Superadmin's config; confirmed by inspection and by the disposable test's own deliberately-unreachable dummy `CORE_API_URL` never being hit |
| Rollback tested | **PARTIAL** | Config-level rollback (`AUTH_PROVIDER=core`) is the live default throughout — never needed to be exercised as a "rollback" because it was never switched on `dev-labs`/`dev-superadmin-backend` in the first place. A real container-level rollback point exists (`blumax-labs:dev-prev`, pre-existing) but `docker commit`-based re-snapshotting failed due to a pre-existing, unrelated containerd content-store gap — noted, not blocking |

## Logout / revocation (documented, not implemented — per explicit instruction)

Empirically reproduced against the real deployed services: a Blumax Auth
logout (204, refresh token revoked) does **not** invalidate an
already-issued access token at the consumer level — the same access
token worked against Superadmin (HTTP 200) immediately after logout.
This is the same known, accepted limitation as Core's own stateless-JWT
posture today (not a regression). Classification unchanged from Phase
4G-0: acceptable by design for native-login sessions, a documented
limitation for externally-token-bearing (SSO-launched) sessions, bounded
by the 15-minute access-token lifetime. No new revocation architecture
was built, per the brief's explicit instruction.

## 1–4. Files modified / created / deleted / DEV infrastructure

**Modified** (local working tree; see each repo's own `git status` for the authoritative list):
- `blumax-labs/labs-backend/app/api/v1/deps.py`, `app/api/v1/auth.py` (facility-scope fix)
- `blumax-labs/labs-backend/tests/test_phase4a_auth_provider_abstraction.py` (fixture correction: added `LabUserFacility` to its schema)

**Created**:
- `blumax-labs/labs-backend/tests/test_facility_scope_fix.py` (12 new tests)
- `blumax-auth/auth-backend/docs/PHASE4G0A_DEV_SERVER_DEPLOYMENT.md`
- `blumax-labs/labs-backend/docs/PHASE4G0A_LABS_AUTH_MIGRATION.md`
- `blumax-labs/labs-backend/docs/PHASE4G0A_FACILITY_SCOPE_FIX.md`
- `blumax-auth/auth-backend/docs/PHASE4G0A_REAL_DEV_EXPORT_DRY_RUN.md`
- `blumax-auth/auth-backend/docs/PHASE4G0A_FINAL_REPORT.md` (this file)
- `dev-infra/apps/auth/docker-compose.yml`, `dev-infra/config/generated/apps/auth.env`, `dev-infra/config/generated/apps/auth-migrate.env` (new dev-infra artifacts, untracked per that repo's own convention — generated compose/env files are never committed)

**Committed and pushed** (with explicit confirmation before each push):
- `blumax-auth` `dev`: `a0354ae..73de50f` — the entire `auth-backend/` service, first-ever
- `blumax-labs` `dev`: `192f75f..2e260e0` — AUTH_PROVIDER abstraction (Phases 4A-4F work)
- `blumax-superadmin` `dev`: `06c0079..1684f12` — AUTH_PROVIDER abstraction (Phase 3 work)

**Deleted**: nothing, in any repository.

**DEV infrastructure created**:
- Containers: `dev-auth`, `dev-auth-migrate` (ran once, exits). All `p4g0a-*` disposable proof containers (Labs, Superadmin, and their throwaway Postgres/Redis) were created, used, and torn down by phase end.
- Volume: `blumax-dev-auth_auth_devkeys` (persistent signing key).
- **Databases created**: `blumax_auth` (new, dedicated role+database, on the existing shared Postgres server).
- **Redis**: no new instance — the existing shared `dev-redis` container, new logical index 5.
- **Services (re)started**: `dev-auth` (new), `dev-labs` (rebuilt+redeployed with the AUTH_PROVIDER code), `dev-superadmin-backend` (rebuilt+redeployed with the AUTH_PROVIDER code). Neither `dev-labs` nor `dev-superadmin-backend` had its `AUTH_PROVIDER` actually switched — both remain on `"core"`.

## 8–9. Tests executed and results

- Blumax Auth: live endpoint verification (health, JWKS, login, refresh, logout, reuse-detection) — all passed.
- Superadmin: 11-point verification checklist against the real deployed `dev-auth` — all passed.
- Labs: full suite, `python -m unittest discover -s tests` — **765/765 passed** (includes the 12 new facility-scope tests).
- Migration tool: dry run + execute + idempotent re-run against the real 56-row DEV Core export — clean on every run.
- Cross-application identity: 2 live scenarios (Labs-only identity rejected by Superadmin; Superadmin-only identity rejected by Labs) — both confirmed.

## 10. Real DEV data used

Yes — Workstream D used a genuine, read-only export of Core's actual DEV
`users` table (86 total rows; 56 eligible after excluding soft-deleted
and service-account rows), not fabricated or synthetic data. All other
workstreams used disposable, self-created test identities (clearly
labelled `phase4g0a-*`), removed at phase end.

## 11–13. Production — confirmed NO in every respect

- **Production systems touched**: NO.
- **Production database mutations**: NO.
- **Production configuration changes**: NO.

No production credential, DNS record, compose file, or environment
variable was read, referenced, or modified at any point in this phase.
Every action targeted `dev-*` containers, the shared DEV Postgres/Redis,
or local git working trees on `dev` branches.

## 14. Remaining blockers (for Phase 4G-1, not for this phase)

1. **The facility-scope fix is implemented and fully tested but not yet
   deployed anywhere** — not committed/pushed, not built into
   `blumax-labs:dev`, not running on `dev-labs`. Workstream C's own brief
   did not request deployment; this was a deliberate, conservative choice
   to keep this phase's git/deploy footprint minimal for a security fix,
   pending your explicit go-ahead.
2. **Phase 4G-0's production-readiness findings were never re-examined
   against production** in this phase, by design (DEV-only scope). A
   production cutover still requires its own, fresh readiness pass —
   nothing here substitutes for that.
3. The second Labs frontend (`labs-admin-portal-frontend`) remains
   undeployed in any topology, DEV or production — pre-existing,
   unrelated to this phase's work, not touched.

## 15. Can Phase 4G-1 begin?

# STILL BLOCKED

Blocked specifically on the two items above that are this phase's own
responsibility to close — not an open-ended problem. Once (1) the
facility-scope fix is pushed and deployed to `dev-labs` with your
explicit approval, and (2) a fresh production-readiness pass is run
against production's actual current state (which this phase correctly
never touched), Phase 4G-1 planning can reasonably begin. Everything this
phase was asked to prove on the real DEV server — Blumax Auth deployed
and healthy, Labs and Superadmin both capable of authenticating against
it with zero privilege leakage between applications, Core business APIs
fully preserved, and the hardened migration tool validated against real
data — is **done and verified live**.

---

Per this phase's own governing instruction: Phase 4G-1 was not started.
No actual production cutover was performed. Core authentication was not
changed anywhere. No session was invalidated. No production database was
mutated.
