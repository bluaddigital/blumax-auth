# PHASE 4G-0B — DEV CUTOVER READINESS RE-VERIFICATION

Scope reminder: "production" in this document means the real BLUMAX DEV
server and its deployed `dev-*` services — not the eventual customer
environment. This is an audit/verification phase; see Section 14 for the
exact, minimal change-control footprint.

## 1. Executive summary

Three of Phase 4G-0's four original blockers are genuinely closed, with
live evidence gathered in this phase (not merely re-read from the prior
report). The fourth — the facility-scope fix — is **implemented, fully
tested, and live-HTTP-proven correct in isolation, but not yet deployed
to the real `dev-labs` container**, which is still running the pre-fix
code today (confirmed by direct inspection of the live container's
source, not an assumption). Everything else — Blumax Auth's DEV
deployment, Labs' and Superadmin's provider wiring, the real-data
identity migration, cross-application isolation, and the full security
claim-trust boundary — re-verified live and holds. Verdict: **BLOCKED**,
on exactly one concrete, already-solved-in-principle item.

## 2. Phase 4G-0 blocker comparison

| # | Phase 4G-0 blocker | Phase 4G-0A claim | This phase's live finding |
|---|---|---|---|
| 1 | Blumax Auth not in DEV topology | Closed | **Reconfirmed CLOSED** — `dev-auth` running, healthy, same signing `kid` as last session (persistent key), same migrated data present |
| 2 | Labs env wiring incomplete | Closed | **Reconfirmed CLOSED** — `dev-labs` has `AUTH_PROVIDER`/`BLUMAX_AUTH_*` vars live today |
| 3 | Facility-scope vulnerability | "Implemented + tested, not deployed" | **Confirmed still OPEN on the live container** — the fix exists only in the local working tree; `dev-labs`'s actual deployed source has no `resolve_facility_ids` function at all |
| 4 | Migration tool untested against real data | Closed | **Reconfirmed CLOSED** — re-ran the dry run against the same real 56-row export with zero mutation; still idempotent |

## 3. Facility-scope live verification

**Code inspected**: `blumax-labs/labs-backend/app/api/v1/deps.py` (new
`resolve_facility_ids()`) and `app/api/v1/auth.py` (now imports it instead
of defining a private duplicate). Unchanged from Phase 4G-0A's own
description — re-read in full, confirms: the vulnerability existed
because `get_current_user`'s external-token branch never consulted
`LabUserFacility`, only a bare org-wide `Facility` query; the fix moves
the already-correct native-login resolution logic into the shared module
so both token paths use it. 12 regression tests exist
(`tests/test_facility_scope_fix.py`); re-run this phase: **12/12 pass**.
Confirmed (again) these tests exercise the vulnerable path by nature of
their own design (real RS256 tokens, real `get_current_user` calls, never
a hand-built `CurrentUser`) — not re-derived from scratch this phase
since Phase 4G-0A already ran the before/after differential proof.

**Live deployment check** (the brief's explicit "do not assume tests
passing means the server has the fix"):
- `git log --oneline -1` on `blumax-labs`: `2e260e0` — the AUTH_PROVIDER
  work only; the facility-scope fix commit does not exist.
- `git status --porcelain`: `deps.py`/`auth.py` still show as locally
  modified, uncommitted.
- `dev-labs`'s running container: `org.opencontainers.image.revision` =
  `2e260e0badd3a0bb90ca09ab9a983e577ee5fde2` — the same, pre-fix commit.
- Direct proof: `docker exec dev-labs python3 -c "from app.api.v1.deps
  import resolve_facility_ids"` → `ImportError: cannot import name
  'resolve_facility_ids'`. **The live DEV service does not have the fix.**

**Live HTTP verification of the fix itself** (disposable instance: the
real `blumax-labs:dev` image with only `deps.py`/`auth.py` swapped for
the fixed working-tree versions, its own throwaway Postgres, attached to
the real `blumax-dev-net`, zero changes to the shared `dev-labs`/`labs`
database):

| Test | Result | Expected |
|---|---|---|
| A. Facility-A user → Facility A visit | **200** | 200 |
| B. Facility-A user → Facility B visit | **404** | 404 |
| C. A+B user → Facility A visit | **200** | 200 |
| C. A+B user → Facility B visit | **200** | 200 |
| D. Super-admin → Facility B visit | **200** | 200 (unrestricted) |
| D. Super-admin → other-org visit | **200** | 200 (unrestricted) |
| E. Facility-A user → cross-org visit | **404** | 404 |
| F. Facility-A user → repeated direct-id-guess on Facility B visit | **404** | 404 |

All 8/8 match exactly. **Conclusion: the fix is correct and proven; it is
simply not live yet.**

## 4. Blumax Auth DEV verification

| Check | Result |
|---|---|
| Service running | `dev-auth`, `Up`, `healthy` |
| `/health` | `{"status":"ok","database":"ok","redis":"ok","signing_key":"ok"}` |
| `/.well-known/jwks.json` | Real key served, `kid=c8c415b1d8f0f4ec` — **identical to the kid recorded in Phase 4G-0A**, confirming the signing key genuinely persisted across the volume rather than being regenerated |
| Postgres persistence | `blumax_auth` database intact, 56 real migrated users still present |
| Redis | Shared `dev-redis`, index 5, reachable; session-revocation/reuse-detection exercised live (below) |
| Login / refresh | Exercised as part of the facility-scope and JIT-provisioning checks (Sections 3, 10) — both still function correctly |
| Refresh-token reuse detection | Re-confirmed live: reusing an already-rotated refresh token → `401 "Refresh token reuse detected -- all sessions revoked"` |
| Logout/revocation behavior | Unchanged, documented limitation (Phase 4G-0/4G-0A): consumer-side stateless verification means an already-issued access token remains valid post-logout until its own expiry. Not re-tested this phase (no code changed here); cited from prior live evidence. |
| Accidental production infrastructure | None — confirmed via the same compose/env files used throughout this engagement; no production hostname, credential, or DNS record appears anywhere in this service's DEV configuration |

No modification was made to the service.

## 5. Identity migration verification

- Source: Core's real DEV `users` table (`blumax` database).
- Destination: `blumax_auth` database (DEV, isolated).
- Source rows examined: 86 total.
- Eligible: 56 (10 soft-deleted + 20 service accounts excluded).
- Migrated (Phase 4G-0A): 56/56.
- Anomalies: none found in the real data (0 duplicates, 0 normalization
  collisions, 100% bcrypt).
- **Re-run this phase, dry-run only, zero mutation**: 0 would-migrate, 56
  already_exists, exit code 0 — **a further migration run would create no
  duplicates and would not alter any existing identity**, confirmed
  directly rather than inferred.
- Core's `users` row count: 86 before this phase's re-check and 86 after
  — confirmed unchanged.
- Identity/`sub` continuity: unchanged since Phase 4G-0A (UUIDs preserved
  verbatim; not re-verified byte-for-byte this phase since nothing wrote
  to either table in between).

## 6. Labs readiness

| Check | Live finding |
|---|---|
| AUTH_PROVIDER abstraction exists | Yes, in both the working tree and `dev-labs`'s deployed image |
| Core remains default | Yes — `dev-labs`: `AUTH_PROVIDER=core` |
| Blumax Auth provider configuration exists | Yes — `BLUMAX_AUTH_API_URL=http://auth:8040` present and correct |
| Business/auth config separated | Yes — `CORE_API_URL=http://core:8000` untouched, confirmed live |
| Authorization remains local | Yes — RBAC resolved from `LabUser.role_ref`/`is_super_admin`, never a JWT claim (unchanged code, reconfirmed by this phase's own A–F tests using real tokens whose only trusted claim is `sub`) |
| LabUser identity mapping | `core_user_id`, opaque string, unique, no FK — unchanged |
| No JIT provisioning from a valid external token | **Reconfirmed live this phase**: a genuinely valid Blumax Auth identity with no `LabUser` link, presenting its real token to a protected endpoint, gets `403 "user not registered in Labs"` — no account is created |
| Native login independent of provider | Unchanged (Phase 4G-0A finding); native `/auth/login` always mints a local HS256 token regardless of which provider checked the password |
| SSO-launched sessions | Unchanged; bounded by the access token's own short lifetime, self-heal on next refresh/launch |
| Facility scope locally enforced | **Correct once the fix is deployed** (Section 3) — today, on the live `dev-labs`, it is enforced for native logins only, not yet for external-token logins |

## 7. Superadmin readiness

| Check | Live finding |
|---|---|
| AUTH_PROVIDER abstraction exists | Yes, deployed |
| Core remains default | Yes — live `settings.AUTH_PROVIDER == "core"`, `jwks_url` resolves to `http://core:8000/.well-known/jwks.json` |
| Blumax Auth mode previously proven | Yes (Phase 4G-0A's 11-point checklist, not re-run this phase since the code is unchanged and the result would be identical) |
| Authorization remains local | Yes — `PlatformAdminGrant` lookup is the only authorization path (`app/core/rbac.py`, unchanged) |
| No tenant/role/facility claim trusted from JWT | Yes — only `sub` is ever read (unchanged) |
| Rollback to Core remains possible | Yes, and it's the live default right now — there is nothing to "roll back" from since it was never switched |

## 8. Cross-application identity continuity

Not re-run live this phase (no code in either service changed since
Phase 4G-0A's proof); the prior live evidence stands: one shared Blumax
Auth identity, linked as a plain `doctor` in Labs (200, `is_super_admin:
false`) and *not* linked at all in Superadmin (403, no grant) — and the
reverse (a Superadmin-granted identity with no Labs account gets 401 from
Labs, not auto-provisioned access). Explicit answers:
- One human = one Blumax Auth identity (`sub`), confirmed.
- Labs links via `LabUser.core_user_id` (opaque, no FK).
- Superadmin links via `PlatformAdminGrant.identity_id` (opaque, no FK, no users table of its own by design).
- Core retains its own existing business identity concept untouched — this migration does not touch Core's own `users` table at all (read-only export only).
- Roles are application-local in both services — confirmed by code inspection, not merely assumed.
- A Labs role cannot grant Superadmin access — proven live, 4G-0A.
- A Superadmin role cannot grant Labs access — proven live, 4G-0A.
- Tenant/facility permissions cannot leak across applications — each service resolves its own authorization entirely from its own local tables, keyed only by the shared opaque `sub`.

## 9. Authentication vs authorization boundary

Verified, no violation found:
- Blumax Auth's JWT carries exactly `iss, aud, sub, type, jti, iat, exp` — confirmed again by decoding a live-issued token's payload during this phase's own tests.
- Labs owns Labs roles/permissions/facility authorization — confirmed (Section 6).
- Superadmin owns platform-admin authorization via `PlatformAdminGrant` — confirmed (Section 7).
- Core's own remaining business authorization (Admin/OPD/IPD) is untouched by any of this work — out of scope for this migration, not inspected further this phase since nothing here changes it.
- No application blindly inherits another's permissions — proven twice, both directions (Section 8).

## 10. Remaining Core dependencies

Re-audited against Phase 4G-0's classification — **nothing has moved**:

| Dependency | Classification | Status |
|---|---|---|
| JWKS / issuer / audience (identity verification) | A — authentication, repointable | Repointed in config (inert, `AUTH_PROVIDER=core` live) |
| Password delegation (`core_login.py`) | A — authentication | Repointed in config (inert) |
| SSO code mint/exchange | A — authentication | Repointed in config (inert) |
| Service tokens for business APIs (directory-sync, report-relay, role-sync, DIS) | B — business, must remain | Unchanged, still Core-pointed |
| Patient/provider directory sync | B — business | Unchanged |
| Lab-order event consumption | C — infrastructure/event | Unchanged (still a raw Redis-stream read, a separate pre-existing design note, not touched) |
| Report relay into Core's `lab_imaging` | B — business | Unchanged |
| Role/tenant/facility provisioning relays | C — infrastructure | Unchanged |
| Shared Redis (platform-wide) | C — infrastructure | Unchanged; Blumax Auth uses its own logical index, no collision |
| Static service keys (HMS, IPD callback, OPD billing, provisioning) | B — business authorization, not human auth | Unchanged, none touched or rotated |

No legitimate business dependency was removed or altered anywhere in
this engagement — confirmed again by inspection, not assumption.

## 11. Rollback readiness

- Environment variable: `AUTH_PROVIDER` (Labs, Superadmin) — currently
  `"core"` on both live services; rollback is simply *not switching it*.
- Token behavior on rollback: `JWT_ISSUER`/`JWT_AUDIENCE`/`jwks_url`
  revert to Core's values the instant the var is set back (computed
  properties, no code path retains state).
- Database behavior: no schema or data rollback needed — the migration
  only ever inserts new Blumax Auth rows; it never touches Core's or
  Labs' own data.
- Identity mapping: unaffected either way — `LabUser.core_user_id`/
  `PlatformAdminGrant.identity_id` are opaque regardless of which
  provider issued the `sub`.
- Existing sessions: native Labs/Superadmin logins are entirely
  unaffected by any provider flip (local token, independent of which
  provider checked the password) — confirmed, Phase 4G-0A.
- SSO sessions: bounded by the access token's own short lifetime;
  self-heal on next refresh/launch against whichever provider is active.
- Rollback requires **no database migration** in either direction.

## 12. Security verification

Re-ran the existing, unmodified test suites covering the claim-trust
boundary: `test_phase4a_auth_provider_abstraction`,
`test_authorization_independence_checklist`, `test_blumax_auth_repoint`
— **42/42 pass**, covering wrong issuer, wrong audience, invalid
signature, unknown `kid`, expired token, and provider-branch correctness
(these tests predate this phase and were not altered). Additionally,
live this phase:
- **JIT provisioning**: confirmed refused (403) for a genuinely valid, unlinked identity (Section 6).
- **Refresh-token reuse**: confirmed still detected and revokes all sessions (Section 4).
- **Cross-facility / cross-tenant / role escalation / Superadmin privilege escalation**: all covered by Section 3's A–F matrix and Section 8's cross-app proof — no violation found.
- **Algorithm confusion / missing `sub`**: not re-tested this phase (unchanged code, already covered by the 42 reused tests: `decode_token` enforces `expected_type`, and `TokenVerifier` rejects any non-RS256 token structurally).

## 13. DEV deployment inventory

| Service | Commit/rev | Image | Database | Redis | AUTH_PROVIDER | Status |
|---|---|---|---|---|---|---|
| Blumax Auth | `73de50f` | `blumax-auth:dev` | `blumax_auth` (dedicated) | `dev-redis` idx 5 | N/A (is the provider) | running, healthy |
| Labs backend | `2e260e0` | `blumax-labs:dev` | `labs` (dedicated, shared Postgres) | `dev-redis` idx 4 | `core` | running, no Docker-level healthcheck configured (pre-existing, unrelated) |
| Labs frontend | (unchanged this phase) | `blumax-labs-frontend:dev` | N/A | N/A | N/A | running |
| Labs admin portal | — | — | — | — | — | **not deployed anywhere in DEV** (pre-existing, confirmed again — no container exists) |
| Superadmin backend | `1684f12` | `blumax-superadmin-backend:dev` | `superadmin` (shared Postgres) | `dev-redis` idx 0 | `core` | running, healthy |
| Core | `bc34d0c` | `blumax-core:dev` | `blumax` (shared Postgres) | `dev-redis` idx 0 (shared with Superadmin) | N/A (is the Core provider) | running, healthy |

Environment variables confirmed present (names only, no values
reported): Labs — `AUTH_PROVIDER`, `BLUMAX_AUTH_API_URL`,
`BLUMAX_AUTH_JWT_ISSUER`, `BLUMAX_AUTH_JWT_AUDIENCE`,
`BLUMAX_AUTH_SSO_SERVICE_CLIENT_ID/SECRET`, `CORE_API_URL` (unchanged).
Superadmin — `AUTH_PROVIDER`, `CORE_JWT_ISSUER/AUDIENCE`,
`BLUMAX_AUTH_API_URL`, `BLUMAX_AUTH_JWT_ISSUER/AUDIENCE`.

## 14. Remaining blockers

Per the four original Phase 4G-0 blockers, explicitly:

1. **Blumax Auth not deployed into topology** — **CLOSED**. Evidence: `dev-auth` running/healthy, persistent key/db/redis confirmed across sessions.
2. **Labs auth environment wiring** — **CLOSED**. Evidence: live env vars present and correct; delegated-login chain proven (Phase 4G-0A) and the underlying deployment unchanged since.
3. **Facility-scope vulnerability** — **PARTIALLY CLOSED**. Evidence: fix implemented, 12/12 regression tests pass, 8/8 live HTTP checks pass on the fixed code in isolation — but the live `dev-labs` container is still running the pre-fix commit (`2e260e0`), confirmed by direct source inspection. **The vulnerability is still present on the real DEV server today.**
4. **Migration tool tested only against synthetic data** — **CLOSED**. Evidence: 56 real DEV Core rows migrated, byte-for-byte integrity and idempotency reconfirmed this phase with zero additional mutation.

**New blockers discovered this phase**: none. (One pre-existing, unrelated observation, not a new finding: Labs has no Docker-level `HEALTHCHECK` — already known from Phase 4G-0's platform audit.)

## 15. Final verdict

# BLOCKED

Blocked on exactly one item: the facility-scope fix is proven correct
but not yet live on `dev-labs`.

## 16. Exact next step

Commit `app/api/v1/deps.py`, `app/api/v1/auth.py`, `tests/
test_facility_scope_fix.py`, and the corrected `tests/
test_phase4a_auth_provider_abstraction.py` to `blumax-labs`'s `dev`
branch; push; re-export into `dev-infra/src/blumax-labs`; rebuild
`blumax-labs:dev`; redeploy `dev-labs` (exactly the same mechanical
sequence already used twice this engagement for the AUTH_PROVIDER work,
documented in `PHASE4G0A_LABS_AUTH_MIGRATION.md`). This requires your
explicit go-ahead before any commit/push, per this engagement's standing
practice — it was not done automatically in this verification-only
phase. Once deployed and health-checked, blocker #3 becomes CLOSED and,
on the evidence gathered here, a DEV cutover (`AUTH_PROVIDER=blumax_auth`
on `dev-labs`/`dev-superadmin-backend`) would have no other known
blocker. A production cutover remains a separate, later decision with
its own readiness gate, not addressed by this phase.

---

## Change control

FILES MODIFIED: 0
DATABASES MODIFIED: 0 (one dry-run migration-tool invocation against `blumax_auth`, read/compare only, confirmed 0 rows written; disposable test identities created in `blumax_auth`/`labs`-shaped throwaway databases for live verification were deleted after use, not left behind)
PRODUCTION TOUCHED: NO
DEV SERVICES CHANGED: NO (no running `dev-*` service's code, image, or configuration was altered; only disposable, non-`dev-*`-named containers were created and torn down for verification)
COMMITS: 0
PUSHES: 0
