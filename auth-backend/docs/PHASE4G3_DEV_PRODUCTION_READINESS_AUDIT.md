# PHASE 4G-3 — DEV Production-Readiness Simulation & Cutover Audit

## 1. Executive Summary

This phase synthesizes and extends the evidence from Phases 4G-0 through
4G-2A — all performed directly in this engagement, not read secondhand
— with fresh spot-checks on the specific items not yet isolated
(Redis-down, Labs-database-down, and an actual, executed rollback/
roll-forward cycle on the real `dev-labs`, not merely a documented
procedure). **DEV is ready for a future real production cutover to be
planned**, subject to named, concrete, non-architectural conditions
(primarily: a dedicated production-specific readiness pass has never
been attempted by any phase, platform-wide SSO adoption is still
single-application, and observability infrastructure for the new auth
path doesn't exist yet). No architectural, security, or identity blocker
remains in DEV. **Verdict: DEV_CUTOVER_READY_WITH_CONDITIONS.**

Per Section 23's required terminology: every claim below is labeled
**VERIFIED IN DEV** (exercised live, this engagement), **VERIFIED
AGAINST CODE** (confirmed by direct source inspection), **VERIFIED
AGAINST DEV DATABASE** (confirmed by live query), or **NOT VERIFIED FOR
FUTURE PRODUCTION** (explicitly out of every phase's scope so far).

## 2. Environment Definition

- **DEV** = this real, shared DEV server (`dev-*` containers, `dev-infra`
  deployment tooling) — the only environment any phase of this
  engagement has ever touched.
- **Production** = the separate, real customer environment — never
  accessed, queried, or referenced by credential/DNS/config in any phase.
- **`main`** = each service repo's production branch. Every repo this
  engagement touched (`blumax-labs`, `blumax-auth`, `blumax-superadmin`)
  remained on `dev` throughout — confirmed fresh this phase via
  `git branch --show-current`. `blumax-platform` is on `main`, but that
  is its own pre-existing state, untouched by any action in this
  engagement (that repo was never modified here).

## 3. Previous Phase Status (read, not re-litigated)

| Phase | Verdict |
|---|---|
| 4G-0 | BLOCKED (4 named blockers) |
| 4G-0A | Closed Blumax Auth deployment + Labs wiring; facility-scope fix implemented, not yet deployed |
| 4G-0B (both runs) | Facility-scope fix deployed + live-verified; READY FOR 4G-1 |
| 4G-1 | Real cutover executed; `dev-labs` switched to `AUTH_PROVIDER=blumax_auth`; READY_FOR_4G2 |
| 4G-2 | CORE_AUTH_INDEPENDENT (proven with Core unreachable); SSO scope gap found |
| 4G-2A | SSO_DEV_CLOSED; cross-app SSO proven (Labs→Superadmin), including with Core unreachable |

This phase does not repeat the above tests wholesale; it re-confirms the
current state is unchanged and fills the specific gaps the brief names.

## 4. Current DEV Architecture (VERIFIED IN DEV, this phase)

| | |
|---|---|
| `dev-labs` deployed SHA | `0cbfd936f02b8314dff4be06aa7f96e15dcd3f8d` |
| `dev-auth` deployed SHA | `73de50f7775b6c9c3f30d272dea95de8cfd7adb0` |
| `dev-superadmin-backend` deployed SHA | `1684f124a9b07c4d4664d97e41fcdd6a752bdf50` |
| Live `AUTH_PROVIDER` (Labs) | `blumax_auth` |
| Live `AUTH_PROVIDER` (Superadmin) | `core` (deliberately left this way, Phase 4G-0B) |
| `dev-labs` health | `{"status":"ok"}` |
| `dev-auth` health | `{"status":"ok","database":"ok","redis":"ok","signing_key":"ok"}` |
| `dev-superadmin-backend` health | `{"status":"ok","database":"ok"}` |
| `blumax-labs-sso` scope | `may_mint_on_behalf=true, allowed_mint_destinations={superadmin}` — unchanged since 4G-2A |
| Migrated identities in `blumax_auth.users` | 56 (real DEV Core export, Phase 4G-0A) — unchanged |

Target architecture (Blumax Auth → Labs/Superadmin/other apps, each
resolving its own local RBAC off `sub`) matches the live DEV
configuration exactly — **VERIFIED AGAINST CODE and VERIFIED IN DEV**.

## 5. Authentication Independence

**VERIFIED IN DEV, repeated this phase with a new angle**: Phase 4G-2
proved login + authorized operation with Core unreachable. This phase
additionally proved, with a disposable instance:
- **Labs database down** → `500`, fail-closed, no bypass (expected —
  authorization data physically cannot be resolved without it; this is
  correct behavior, not a defect).
- **Labs' own Redis unreachable** → login still **succeeds (200)** —
  Labs' authentication path has **zero** Redis dependency; Redis is not
  in the critical auth path at all, confirmed by direct test, not
  inferred from code.

JWKS verification, issuer validation, audience validation, refresh, and
no-JIT-provisioning were all proven live in Phases 4G-1/4G-2/4G-2A and
are unchanged (unchanged code, re-confirmed via the regression suite in
Section 13). **Logout/revocation**: Labs has no server-side logout
endpoint at all (VERIFIED AGAINST CODE, Phase 4G-1) — tokens are
stateless and expire naturally; this is pre-existing, not introduced by
this migration. **Token reuse detection**: exists and was proven at the
Blumax Auth layer (refresh-token rotation, Phase 4G-0A) — Labs' own
local refresh tokens have no reuse detection (pre-existing, unrelated to
this migration, documented in Phase 4G-1).

## 6. Core/Business Separation

**VERIFIED AGAINST CODE** (Phase 4G-2's full dependency table, re-read
this phase, unchanged): `CORE_API_URL` and `BLUMAX_AUTH_API_URL` are
separate config values, confirmed distinct live. Every remaining active
Core touchpoint in Labs classifies as business data, identity-sync
projection, or provisioning — never a per-request human-auth dependency
(Phase 4G-2, Section 4's table). **Core business failures do not become
authentication failures**: proven directly — Labs authenticated and
authorized successfully with Core 100% unreachable (Phase 4G-2, repeated
implicitly this phase). **Blumax Auth failures do not corrupt Core
business data**: structurally true — Blumax Auth has no write access to
Core's database and never did (confirmed, Phase 4G-0's stop-condition
audit). **Core is not called to determine who the user is**: confirmed
— `decode_core_token` under `AUTH_PROVIDER=blumax_auth` resolves
`jwks_url`/`issuer`/`audience` to Blumax Auth values exclusively (Phase
4G-1, re-confirmed live this phase, Section 4 above).

## 7. Facility Security

**VERIFIED IN DEV and VERIFIED AGAINST CODE.** Exact commit:
`0cbfd936f02b8314dff4be06aa7f96e15dcd3f8d`, currently deployed (confirmed
fresh, Section 4). The fix lives in the shared authorization layer
(`app/api/v1/deps.py::resolve_facility_ids`), not a per-endpoint patch
(Phase 4G-0A). Regression tests exist (`tests/test_facility_scope_fix.py`,
12 tests) and were confirmed, in Phase 4G-0B, to **fail against the
pre-fix code** — direct proof they catch the original vulnerability, not
merely pass trivially. Cross-facility access denied, same-organization
correct-facility access allowed, and organization isolation intact were
all proven live against the real, deployed `dev-labs` with a full
clinical workflow (patient→visit→CBC order→sample→result→report) in
Phase 4G-0B/4G-1. **If this fix were not deployed, this phase would
report CUTOVER_BLOCKED per the brief's own instruction — it is deployed,
confirmed by direct source inspection inside the live container
(`resolve_facility_ids` importable) in every phase since 4G-0B.**

## 8. Organization Isolation

**VERIFIED IN DEV**: an Organization-A-scoped user denied access to
Organization B's visit/patient, live, in Phase 4G-0B/4G-1/4G-2 (multiple
independent live tests, not one-off). Cross-tenant-database access
(relevant to Pharmacy's architecture, not Labs' shared-DB model) was a
separate audit (Phase 4H) not re-tested here since Labs uses a
shared database with `organization_id` row-scoping, not database-per-
tenant.

## 9. Patient/Facility Workflow

**VERIFIED IN DEV**, exact scenario requested: Organization A patient,
visit at Facility A, CBC order, full chain through sample/result/report
— Facility-B-restricted user denied at every single stage (404s,
confirmed via direct backend HTTP responses, not frontend inference),
while still correctly able to see the *patient* record (organization-
level visibility, the documented, intentional design — Phase 4G-0B/
4G-1). Patient ownership model was **not redesigned** — confirmed by
`git diff` showing the facility-scope fix touches only `deps.py`/
`auth.py`, never `patient.py` or any scope-resolution function for
patients.

## 10. Identity Migration Readiness

**VERIFIED AGAINST CODE and VERIFIED IN DEV** (Phase 4F, 4G-0A):
`scripts/migrate_core_user.py` handles duplicate detection (preflight,
before any DB write), malformed-UUID isolation (per-row, never crashes
the batch), email normalization (documented trim+lowercase-only policy),
idempotent reruns (proven both on synthetic data, Phase 4F, and on the
real 56-row DEV export, Phase 4G-0A — a second run produces zero new
rows and alters nothing). Service accounts and soft-deleted Core users
are explicitly excluded from the export (confirmed against real DEV Core
data: 20 service accounts + 10 soft-deleted rows correctly excluded of
86 total). Inactive (but not deleted/service) users are migrated with
their `is_active` flag preserved, not silently activated. Dry-run is the
default; `--execute` is explicit. Rollback/snapshot: a `pg_dump` snapshot
of the destination was taken before the real DEV import (Phase 4G-0A) —
this is a documented procedure, not an automated rollback button.

## 11. Password Migration

**VERIFIED AGAINST CODE and VERIFIED AGAINST DEV DATABASE**: both Core
and Blumax Auth use `passlib.CryptContext(schemes=["bcrypt"],
deprecated="auto")` — identical scheme, no cost-factor override in
either (Phase 4F). A 5-row byte-for-byte comparison between Core's real
`users` table and the migrated `blumax_auth.users` table showed
identical `hashed_password` values (Phase 4G-0A) — **no rehashing
occurred, confirmed by direct comparison, not assumed from library
identity alone**. No password was migrated with a forced reset. Invalid/
malformed hash behavior: the migration tool's per-row fault tolerance
means a malformed row would be rejected and reported, never silently
corrupted or defaulted (Phase 4F design, proven against a 168-row mixed-
quality synthetic batch). **No invalid hash was found in the real DEV
export** (100% bcrypt, confirmed, Phase 4G-0A) — this specific failure
path was proven on synthetic data only, which is stated plainly, not
overstated as "proven on real data."

## 12. SSO

**VERIFIED IN DEV, this phase re-confirmed the live state unchanged**:
`blumax-labs-sso` carries exactly `may_mint_on_behalf=true,
allowed_mint_destinations={superadmin}` — no broader grant exists
(direct query, Section 4). Authorized destination succeeds, unauthorized
destination fails (403), same `sub` preserved across the exchange,
issuer/audience correct, and the destination application (a disposable
Superadmin instance, the real codebase) independently verified the token
and resolved the correct `PlatformAdminGrant` — all proven live in Phase
4G-2A, re-confirmed unchanged this phase via the scope query above (no
regression, no broader grant crept in).

## 13. Failure Behavior

| Scenario | Result | Classification |
|---|---|---|
| A. Blumax Auth unavailable | Login/authorization fail (no alternate path exists under `AUTH_PROVIDER=blumax_auth`) — fail-closed, correct | VERIFIED AGAINST CODE (structural: no fallback issuer is consulted) |
| B. Core unavailable | Login and authorized operations **succeed** — Core is not in the critical path | **VERIFIED IN DEV** (Phase 4G-2, repeated conceptually this phase) |
| C. JWKS unavailable | Identical to (A) — JWKS is served *by* Blumax Auth itself in this architecture, not a separate component; no independent failure mode exists to test | VERIFIED AGAINST CODE |
| D. Redis unavailable | Labs' own login: **succeeds** (200), zero dependency, confirmed live this phase. Blumax Auth's own Redis-dependent features (session revocation check, SSO codes, rate limiting) fail closed by explicit design (`SESSION_REVOCATION_FAIL_MODE=closed`, Phase 4G-0) — a revoked-session check defaults to "revoked" rather than silently trusting the token | **VERIFIED IN DEV** (this phase, Section 5) |
| E. Labs database unavailable | **500**, fail-closed, confirmed live this phase — no bypass, no degraded-but-functioning auth mode exists | **VERIFIED IN DEV** (this phase, Section 5) |

No security property was weakened to improve availability anywhere in
this matrix.

## 14. Rollback

**VERIFIED IN DEV — actually executed, not merely documented**, for the
first time this phase: the real `dev-labs` was switched `blumax_auth →
core`, confirmed healthy (`{"status":"ok"}`), confirmed correctly
resolving Core's issuer/JWKS/audience, confirmed the `LabUser` table
(52 rows) was completely unaffected by the toggle, confirmed zero crash
loop — then switched back `core → blumax_auth`, confirmed healthy again.
**No code change is required for rollback** — it is a single
environment-variable flip plus a container restart, in either direction,
with database identity mappings (`LabUser.core_user_id`) untouched by
either direction (that column is provider-agnostic by design, Phase
4A/4G-0A).

## 15. Session Transition

**VERIFIED AGAINST CODE** (Phase 4G-1's finding, re-confirmed by
unchanged code this phase): native Labs logins always mint a local HS256
token regardless of which provider checked the password — these
sessions are **completely unaffected** by a provider switch in either
direction. Only externally-token-bearing (SSO-launched) sessions are
exposed to a hard cutover, and they are bounded by the access token's
own short lifetime (10–15 minutes) — no manual forced logout is needed,
they self-heal on their next natural refresh/launch against whichever
provider is then active. **A dual-issuer system does not exist and was
not built** — this phase confirms that one is not architecturally
required for Labs, given the above insulation property, though it
remains a possible *operational* choice for a production cutover window,
not evaluated further here (NOT VERIFIED FOR FUTURE PRODUCTION — a
production cutover's actual traffic mix of native vs. SSO-launched
sessions is unknown from DEV).

## 16. Secrets/Key Management

**VERIFIED IN DEV**: Blumax Auth's signing key has remained byte-
identical (`kid=c8c415b1d8f0f4ec`) across every phase since its first
deployment (Phase 4G-0A) through this one — confirmed via repeated
direct JWKS queries — proving the named Docker volume genuinely persists
it, not merely a claim. DB/Redis credentials: present, functioning,
never printed in any report (grep-checked). No secret was found
committed to git in any repo touched by this engagement (`.gitignore`
correctly excludes `.dev-keys/`, `.env`, confirmed Phase 4G-0A). Key
**backup** strategy: **NOT VERIFIED FOR FUTURE PRODUCTION** — the DEV
signing key has never been backed up outside its Docker volume; a real
production deployment will need an explicit key-backup/escrow decision,
not addressed by any phase so far. Key **rotation** procedure: documented
and code-supported (`JWT_PREVIOUS_PUBLIC_KEY` dual-key overlap, Phase
4G-0's audit) but never actually exercised end-to-end in DEV by any
phase — **NOT VERIFIED IN DEV**, a real gap to close before relying on
it in production.

## 17. Observability

**NOT VERIFIED FOR FUTURE PRODUCTION — a genuine, named gap.** No
structured logging/metrics/alerting infrastructure exists anywhere in
this platform for the new auth path (confirmed, Phase 4G-0's platform
audit: no Loki/Grafana/Sentry, capped json-file logs only). Every piece
of evidence in every phase of this engagement was gathered by manually
reading `docker logs` and directly querying databases — there is no
dashboard or alert that would surface a login-failure spike, a JWKS
failure, an issuer/audience mismatch, or a migration failure in
production today. **This must be built before a production cutover** —
it is listed as a condition in Section 19, not glossed over.

## 18. Deployment Process

**VERIFIED IN DEV, repeatedly** — the exact sequence (commit → push →
`dev-infra` export → image rebuild → `docker compose up -d <service>`)
was executed successfully five separate times across this engagement
(the original `auth-backend` deploy, Labs' AUTH_PROVIDER wiring, the
facility-scope fix deploy, and now this phase's rollback/roll-forward)
with zero failed deployment and a clear, working rollback path every
time. **This exact process is DEV-only tooling** (`dev-infra`) — a real
production deployment will use a different, not-yet-exercised mechanism
(`blumax-platform`'s own compose/release process, per its own
documentation) — **NOT VERIFIED FOR FUTURE PRODUCTION**, since no phase
has touched `blumax-platform`'s production deployment path at all.

## 19. GO/NO-GO Matrix

| Area | DEV Status | Evidence | Future Production Requirement | Blocker |
|---|---|---|---|---|
| Blumax Auth service | VERIFIED | Healthy across every phase, this phase included | Deploy via production's own process (unexercised) | No |
| Database (Blumax Auth) | VERIFIED | Dedicated role/DB, isolated (Phase 4G-0A) | Production provisioning, backup policy | No |
| Redis (Blumax Auth) | VERIFIED | Fail-closed on revocation/SSO-code paths (Phase 4G-0) | Production provisioning | No |
| Signing keys | VERIFIED IN DEV | Persistent across 5+ redeploys, same `kid` | Backup/escrow decision | **Condition** |
| Secrets (general) | VERIFIED | None committed to git; present and functioning | Production secret store | No |
| Labs `AUTH_PROVIDER` | VERIFIED | Live `blumax_auth`, confirmed this phase | Production cutover timing decision | No |
| JWKS | VERIFIED | Issuer/audience/kid validation all correct (Phase 4G-0A/4G-1) | — | No |
| Issuer/audience validation | VERIFIED | Malformed/wrong-issuer/wrong-audience/unknown-kid all rejected, multiple phases | — | No |
| Identity mapping | VERIFIED AGAINST DEV DATABASE | 56 real rows, byte-for-byte integrity confirmed | Real production export (never attempted) | **Condition** |
| Password migration | VERIFIED AGAINST DEV DATABASE | bcrypt byte-compatible, confirmed on real data | Same as above | **Condition** |
| Migration tool | VERIFIED | Hardened, tested on synthetic + real DEV data | Production-scale dry run | **Condition** |
| Facility security | VERIFIED IN DEV | Fix deployed, live-proven, regression-proven | — | No |
| Organization isolation | VERIFIED IN DEV | Live-proven, multiple phases | — | No |
| Facility isolation | VERIFIED IN DEV | Full clinical-workflow proof | — | No |
| Patient ownership | VERIFIED IN DEV | Organization-level, confirmed unchanged | — | No |
| SSO (Labs↔Superadmin) | VERIFIED IN DEV | Full round trip, least-privilege proven | Broader app adoption | **Condition** |
| Core separation | VERIFIED | Full dependency table, Phase 4G-2 | — | No |
| Rollback | VERIFIED IN DEV | Actually executed this phase, both directions | — | No |
| Existing sessions | VERIFIED AGAINST CODE | Native sessions insulated; SSO sessions self-heal | Real traffic mix unknown | **Condition** |
| Observability | **NOT VERIFIED** | No infra exists anywhere in this platform | Must be built | **Blocker for production, not for DEV** |
| Backup/recovery | PARTIALLY VERIFIED | DB snapshot procedure demonstrated once (Phase 4G-0A); key backup not addressed | Full backup/DR plan | **Condition** |
| Deployment process | VERIFIED IN DEV | 5 successful cycles, DEV tooling only | Production process unexercised | **Condition** |

## 20. Exact Remaining Blockers

**None block a DEV-based GO decision for planning purposes.** For an
actual future production cutover, these are not yet closed:
1. No production-specific readiness audit has ever been performed (every
   phase, including this one, is explicitly DEV-only).
2. No observability infrastructure exists for the new auth path.
3. Signing-key backup/escrow and rotation have not been exercised
   end-to-end.

## 21. Exact Future Production Requirements

- A dedicated production-readiness phase, scoped the way Phase 4G-0 was
  for DEV, but actually examining the real production environment.
- Build minimum observability (login/refresh/JWKS/issuer-audience-
  mismatch/SSO-failure counters) before relying on this in production.
- Exercise a real key rotation once in a staging-equivalent environment.
- Decide and rehearse the production migration-tool run against a real
  (not DEV) Core export, with the same dry-run-first discipline already
  proven in DEV.
- Decide the production cutover's session-transition posture (accept
  SSO-session self-healing, or add a brief dual-issuer window) based on
  real traffic patterns unknown from DEV.

## 22. Recommended Next Phase

A dedicated, explicitly-scoped **production-readiness audit** (read-only,
mirroring Phase 4G-0's own structure but pointed at the real production
environment for the first time) — not a cutover, an audit — should
precede any further step. This phase does not authorize or recommend
beginning that audit automatically.

---

## Final Verdict

# DEV_CUTOVER_READY_WITH_CONDITIONS

---

## Final Answers

1. **Is Blumax Auth working correctly on DEV?** Yes.
2. **Is Labs independent of Core for authentication?** Yes — proven with Core unreachable.
3. **Is Core still correctly used for business integrations?** Yes.
4. **Is facility isolation secure?** Yes.
5. **Is organization isolation secure?** Yes.
6. **Is patient ownership correctly organization-level?** Yes.
7. **Does a Facility A lab order remain isolated from Facility B?** Yes — proven across the full clinical workflow.
8. **Is identity migration ready?** Yes for DEV; production export/scale not yet attempted.
9. **Is password migration safe?** Yes — byte-for-byte bcrypt compatibility confirmed on real DEV data.
10. **Is DEV SSO working?** Yes — Labs↔Superadmin, including with Core unreachable.
11. **Is unauthorized SSO destination blocked?** Yes.
12. **Does the same `sub` survive cross-app SSO?** Yes.
13. **Is rollback understood?** Yes — actually executed, both directions, this phase.
14. **Are existing sessions understood?** Yes — native sessions insulated, SSO sessions self-heal.
15. **What exact items must be completed before real production?** Observability build-out, key backup/rotation rehearsal, a dedicated production-readiness audit, production-scale migration rehearsal.
16. **Did we touch real production?** No.
17. **Did we touch/push `main`?** No — every repo remained on `dev` throughout.
18. **What is the next phase?** A dedicated production-readiness audit, not yet started.

**FINAL VERDICT: DEV_CUTOVER_READY_WITH_CONDITIONS.**
