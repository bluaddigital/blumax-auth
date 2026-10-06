# PHASE 4G-0B — DEV BLOCKER CLOSURE + POST-DEPLOYMENT READINESS VERIFICATION

## 1. Scope

Close exactly the two blockers left open by Phase 4G-0A: (1) deploy the
already-tested facility-scope fix to the real `dev-labs`, (2) perform a
fresh post-deployment DEV readiness verification. DEV-only throughout.
"Production" never means the real customer environment in this document.
No production system, Core authentication behavior, Pharmacy
authentication, or Superadmin authentication was touched.

## 2. Starting state

- `blumax-labs` `dev` branch, commit `2e260e0` (the Phase 4G-0A
  AUTH_PROVIDER work) — the facility-scope fix existed only as an
  uncommitted local diff (`app/api/v1/deps.py`, `app/api/v1/auth.py`,
  plus the new `tests/test_facility_scope_fix.py` and a fixture
  correction in `tests/test_phase4a_auth_provider_abstraction.py`).
- `dev-labs`'s deployed image/container: `blumax-labs:dev` at commit
  `2e260e0` — confirmed, by direct inspection of the running container's
  own source, to **not** contain `resolve_facility_ids` at all
  (`ImportError`). The fix was not live.
- Labs `AUTH_PROVIDER` (live): `core`.
- Blumax Auth DEV (`dev-auth`): healthy, same signing `kid`
  (`c8c415b1d8f0f4ec`) as previously recorded — confirms genuine key
  persistence, not regeneration.
- Superadmin DEV (`dev-superadmin-backend`): `AUTH_PROVIDER=core`, healthy.

## 3. Facility-scope fix verification

Re-read the exact diff in full (reproduced in the commit message, not
duplicated here). Confirmed:
- The fix lives entirely in `app/api/v1/deps.py` (`resolve_facility_ids`,
  a new shared function) — the single authorization/dependency layer
  every protected route already depends on via `get_current_user`.
- It applies uniformly: any endpoint using `Depends(get_current_user)`
  benefits automatically, not a per-route patch.
- Unrestricted-facility behavior (no explicit `LabUserFacility` rows) is
  unchanged — falls back to every active facility in the org, exactly as
  before.
- Super-admin behavior is untouched — `facility_scope()` still returns
  `None` for `is_super_admin=True`, bypassing the facility check
  entirely, before `resolve_facility_ids` is ever relevant.
- No JWT tenant/facility claim is read anywhere in this function —
  `LabUserFacility`/`Facility` are the only inputs.
- Facility authorization is 100% Labs-local data.

**Focused regression tests**: `tests/test_facility_scope_fix.py`, 12
tests — **12/12 pass**.
**Full Labs suite**: `python -m unittest discover -s tests` —
**765/765 pass**.
Both counts are unchanged from Phase 4G-0A's own run, confirming no
drift occurred while the fix sat uncommitted.

## 4. Deployment details

| | |
|---|---|
| Old deployed commit | `2e260e0badd3a0bb90ca09ab9a983e577ee5fde2` |
| New deployed commit | `0cbfd936f02b8314dff4be06aa7f96e15dcd3f8d` |
| Files included | `app/api/v1/deps.py`, `app/api/v1/auth.py`, `tests/test_facility_scope_fix.py` (new), `tests/test_phase4a_auth_provider_abstraction.py` (fixture fix), plus 2 doc files — **nothing else from the working tree** |
| Deployment command | `git commit` + `git push origin dev` (confirmed pushed: `2e260e0..0cbfd93`) → `dev-infra`'s own `export_dev`-equivalent (git fetch into `refs/dev-infra/dev`, `git archive` into `dev-infra/src/blumax-labs`) → `docker compose build labs` → `docker compose up -d labs` |
| Target | `dev-labs` container only, via `dev-infra/apps/labs/docker-compose.yml` |

**Post-deployment checks**: API health `{"status":"ok"}`; deployed
revision label confirms `0cbfd93`; `resolve_facility_ids` importable
inside the live container (the fix is actually there, not merely
assumed); restart count `0` (no crash loop); `labs-migrate` was not
triggered (profile-gated, `up -d labs` only targets the `labs` service);
every other `dev-labs-*` worker/relay container was left untouched,
still on its own prior image — only the `labs` API service itself was
recreated; `AUTH_PROVIDER` confirmed still `core` post-deploy (zero
behavior change for live traffic).

A pre-existing, unrelated Docker image-store quirk (a containerd
content-digest gap, previously observed in Phase 4G-0A too) again
prevented a fresh `docker commit`-based rollback snapshot. The reliable
rollback path is git-based, not image-tag-based: re-export and rebuild
from commit `2e260e0` reproduces the exact prior state (documented in
Section 12).

## 5. Live facility-scope tests

Tested against a disposable instance of the **actual deployed artifact**
(`blumax-labs:dev`, the same image now running as `dev-labs`, no local
source mount — pulling the fix from the image itself), configured for
`AUTH_PROVIDER=blumax_auth` and pointed at the real `dev-auth`, with its
own throwaway Postgres (no shared data touched). This configuration
choice is explained in full below (Section 6) — the live `dev-labs`
container itself was correctly left on `AUTH_PROVIDER=core` throughout,
so the real external-token path could not be exercised via live HTTP
against `dev-labs` directly without presenting it a Core-issued token,
which this phase had no legitimate way to mint.

| Test | Result | Expected |
|---|---|---|
| A. Authorized user + authorized facility | **200** | 200 |
| B. Same user + unauthorized facility | **404** | 404 |
| C. Multi-facility user → facility A | **200** | 200 |
| C. Multi-facility user → facility B | **200** | 200 |
| D. User → facility outside assigned set (other org) | **404** | 404 |
| E. Unrestricted/super-admin → facility B | **200** | 200 |
| E. Unrestricted/super-admin → other-org visit | **200** | 200 |
| F. Super-admin → own facility too | **200** | 200 |

8/8 match exactly. Non-destructive, clearly-labelled disposable data
only; all test identities and containers were deleted after use (an
initial attempt to test directly against live `dev-labs` with real
database test rows was made, found not viable under the live
`AUTH_PROVIDER=core` configuration — see Section 6 — and those rows were
immediately cleaned up rather than left in the real database).

## 6. Blumax Auth DEV re-verification

| Check | Result |
|---|---|
| `/health` | `{"status":"ok","database":"ok","redis":"ok","signing_key":"ok"}` |
| JWKS | Served, `kid=c8c415b1d8f0f4ec` — identical across this and the prior phase, confirming persistence |
| Login / access token | Exercised live as part of Section 5's tests |
| Refresh rotation | Not re-exercised this phase (unchanged code, already proven twice; re-confirming on every phase adds no new information) |
| Logout/revocation behavior | Unchanged, documented limitation (Phase 4G-0/4G-0A/4G-0B-prior): consumer-side stateless verification means a logged-out access token remains valid until its own expiry |
| Reuse detection | Not re-exercised this phase for the same reason — no code in Blumax Auth changed |

No failure occurred; the service was not modified.

## 7. Labs authentication verification

- Labs can authenticate using the Blumax Auth identity path — proven in
  Section 5, against the real deployed image.
- JWT signature verification used Blumax Auth's real JWKS when the
  disposable instance was configured for that path (`AUTH_PROVIDER=
  blumax_auth` → `jwks_url` resolves to `http://auth:8040/.well-known/
  jwks.json`).
- Issuer/audience: `https://auth.dev.blumax.health` / `blumax`, both
  enforced (unchanged verification code).
- `sub` preserved — the same UUID created in `dev-auth` is the `sub`
  verified by Labs and the `core_user_id` that resolves the `LabUser`.
- Labs resolves identity locally (`LabUser` lookup by `core_user_id`,
  never trusting any other token field).
- **Labs-local role, organization, and facility scope remain
  authoritative** — confirmed directly: the minted local token in
  Section 5's test carried `role`, `organization_id`, `facility_ids`
  computed entirely from Labs' own tables, never from the Blumax Auth
  token's claims (which carry none of these, by the thin-JWT design).
- Unmatched identity rejected: re-confirmed implicitly by this
  engagement's prior live tests (Phase 4G-0A); not re-run this phase
  since `get_current_user`'s unmatched-identity branch (line
  `raise HTTPException(status_code=403, ...)`) is untouched by the
  facility-scope diff.
- **No JIT provisioning**: unchanged code path, already proven live in
  Phase 4G-0B (prior verification); the facility-scope fix touches only
  the *scope-resolution* step, which runs strictly after the
  JIT-provisioning check already refused or passed.

The live `dev-labs` container itself was **not** switched to
`AUTH_PROVIDER=blumax_auth` — it remains on `core` throughout this
phase, per the brief's explicit instruction not to perform a
production-style hard cutover.

## 8. Authorization/RBAC verification

No RBAC redesign occurred. `require_role`/`require_super_admin`/
`facility_scope` are byte-identical to before this fix — only the
*input* they receive (`CurrentUser.facility_ids`) is now correctly
computed for external tokens too. Super-admin semantics (`is_super_admin`
bypasses every role and facility check) are untouched and were
specifically re-tested (Section 5, tests E/F).

## 9. Core dependency classification

Re-audited the deployed `deps.py`'s own imports directly inside the live
`dev-labs` container: `app.core.database`, `app.core.security`
(`decode_core_token`/`decode_token` — pre-existing, unchanged, provider-
aware since Phase 4A), `app.models.facility`, `app.models.lab_user`. **No
new Core ORM import, no new Core DB access, no new Core JWKS/business-API
dependency was introduced by this fix.** Classification unchanged from
Phase 4G-0/4G-0A:
- JWKS/issuer/audience/password-delegation/SSO/service-tokens: Category A (authentication, already provider-abstracted, inert on `core` default).
- Patient/provider sync, lab-order events, report relay, role provisioning: Category B/C (business/infrastructure), untouched by this or any prior phase of this engagement.

## 10. Migration-tool readiness

Not re-run this phase (no production access, and nothing about the tool
changed since Phase 4G-0A). Status, restated accurately:
- Tool exists: `blumax-auth/auth-backend/scripts/migrate_core_user.py`.
- Validation rules, dry-run mode, idempotency, duplicate handling,
  malformed-record handling: all exist and were exercised in Phase 4F
  (synthetic) and Phase 4G-0A (real DEV data, 56/56 rows).
- Soft-deleted/service-account handling: explicit exclusion, confirmed
  via the real Core export (10 soft-deleted + 20 service accounts
  correctly excluded).
- No plaintext password is ever logged or printed (confirmed by code
  review, Phase 4F).
- No re-hash required (bcrypt byte-compatible, confirmed Phase 4F/4G-0A).
- Source (Core) data is never modified — read-only transaction only.
- Destination (`blumax_auth`) can be snapshotted — `pg_dump` demonstrated in Phase 4G-0A.
- Rollback strategy: documented (delete the migrated rows / restore the
  pre-import snapshot; Core's own data is never touched so there is
  nothing to roll back on that side).

**Explicitly stated, not glossed over**: this tool has been proven
against real DEV Core data (56 rows, Phase 4G-0A) but **has never been
run against production data, and this phase did not and could not change
that** (no production access exists or was used). It is DEV-proven, not
production-proven.

## 11. Identity continuity

| Link | Mechanism | Status |
|---|---|---|
| Core user UUID/sub → Blumax Auth identity | `scripts/migrate_core_user.py`, preserves the UUID verbatim as `users.id` | **Proven** (Phase 4G-0A, real data) |
| Blumax Auth identity → Labs identity | `LabUser.core_user_id` (opaque string, unique, no FK) | **Proven** (this phase and Phase 4G-0A, live) |
| Blumax Auth identity → Superadmin identity | `PlatformAdminGrant.identity_id` (opaque UUID, no FK, no users table of its own) | **Proven** (Phase 4G-0A, live) |
| Blumax Auth identity → Pharmacy identity | — | **NOT IMPLEMENTED.** Confirmed by inspection: `blumax-pharm` only imports the baseline `blumax_auth` verification library (the same Core-token-verification capability every service already had before this engagement) — it has no `AUTH_PROVIDER` toggle, no Blumax-Auth-specific identity link, and was never touched by this or any prior phase of this engagement, correctly, per explicit instruction ("Do NOT change Pharmacy authentication"). |

**This is classified as a blocker for any eventual platform-wide
cutover that includes Pharmacy — not a blocker for this phase's own
narrow objective** (closing Labs' two Phase 4G-0A blockers), and not a
new problem introduced here; it is a pre-existing, correctly-untouched
scope boundary, stated explicitly rather than silently assumed closed.

## 12. Rollback verification

- `AUTH_PROVIDER=core` remains available and is the live default on both
  `dev-labs` and `dev-superadmin-backend` right now — there is nothing to
  roll back from in terms of provider state.
- Core's issuer/audience/JWKS configuration is untouched and still the
  active trust anchor for both services.
- No destructive schema change exists anywhere in this engagement's work
  — the migration tool only ever inserts new Blumax Auth rows.
- Rollback does not require recreating any user — Labs'/Superadmin's own
  user/grant tables are never touched by a provider-config change.
- **Container-level rollback for this specific deployment**: the
  documented, reliable method is re-exporting and rebuilding from commit
  `2e260e0` (the pre-fix commit) and redeploying — the exact same
  mechanism used to deploy forward, run in reverse. A local image-tag-
  based shortcut was attempted and blocked by a pre-existing,
  unrelated Docker image-store quirk (Section 4); the git-based method
  was not needed and was not executed, since no rollback was required.

## 13. Test counts

| Suite | Count | Result |
|---|---|---|
| Facility-scope regression (`tests/test_facility_scope_fix.py`) | 12 | 12/12 pass |
| Full Labs suite (`python -m unittest discover -s tests`) | 765 | 765/765 pass |
| Live HTTP A–F matrix (this phase) | 8 | 8/8 pass |

## 14. Exact files changed

Committed and pushed to `blumax-labs` `dev` (`2e260e0..0cbfd93`):
- `labs-backend/app/api/v1/deps.py`
- `labs-backend/app/api/v1/auth.py`
- `labs-backend/tests/test_phase4a_auth_provider_abstraction.py`
- `labs-backend/tests/test_facility_scope_fix.py` (new)
- `labs-backend/docs/PHASE4G0A_FACILITY_SCOPE_FIX.md` (new)
- `labs-backend/docs/PHASE4G0A_LABS_AUTH_MIGRATION.md` (new)

`dev-infra` (untracked-by-design generated artifacts, per that repo's own
convention): `src/blumax-labs/*` re-exported; `blumax-labs:dev` image
rebuilt.

## 15. Exact files NOT changed

Every other file in `blumax-labs`, and every file in `blumax-auth`,
`blumax-superadmin`, `blumax-pharm`, `blumax-platform`, and `blumax-
backend` (Core). No config file for any other service was touched. No
database schema was migrated anywhere in this phase.

## 16. Production safety statement

No production system was accessed, queried, or modified. No production
credential, DNS record, or configuration was read or referenced. Every
action in this phase targeted `dev-*` containers, disposable test
containers created and destroyed within this phase, or the `blumax-labs`
GitHub `dev` branch (a shared DEV branch, not `main`, not production).
Core, Pharmacy, and Superadmin authentication behavior were not changed
anywhere — Superadmin's own `AUTH_PROVIDER` stayed `core` throughout and
was not touched by any action in this phase.

## 17. Remaining blockers

| Blocker | Status | Severity | DEV or production |
|---|---|---|---|
| Facility-scope fix not deployed | **CLOSED this phase** — live on `dev-labs`, commit `0cbfd93`, verified | — | DEV |
| Post-deployment readiness verification not performed | **CLOSED this phase** — this report | — | DEV |
| Pharmacy has no Blumax Auth identity continuity mechanism at all | **OPEN, pre-existing, out of this phase's scope** | Blocks a platform-wide (not Labs-only) cutover only | N/A to this phase; relevant to a future, separately-scoped phase |
| Migration tool is DEV-proven only, never run against production | **OPEN, expected, unchanged** | Blocks any production cutover, not a DEV blocker | Production-related |

No new DEV-specific blocker was discovered. No unrelated fix was
introduced — only the facility-scope change, already fully specified by
Phase 4G-0A, was deployed.

## 18. Final verdict

# STILL_BLOCKED

Both of Phase 4G-0A's named blockers (facility-scope deployment,
post-deployment verification) are now closed, with live evidence. The
verdict is `STILL_BLOCKED` rather than `READY_FOR_PHASE_4G_1` strictly
because the brief's own Step 11 standard — "every blocker has objective
evidence" of closure — is not met for a platform-wide cutover: Pharmacy's
identity-continuity mechanism does not exist, and the migration tool
remains DEV-proven only. **For the narrow question this phase was asked
to answer — are Labs' and Superadmin's DEV-side blockers closed? — the
answer is yes, with evidence, in Sections 3–9 above.** A broader
`READY_FOR_PHASE_4G_1` verdict covering Pharmacy and any production step
is out of this phase's scope and would require its own, separately
authorized phase.

---

## Concise summary

- **Verdict**: STILL_BLOCKED (for a full-platform/production cutover; Labs+Superadmin's own DEV blockers are closed)
- **Facility fix deployed?**: YES — `dev-labs` now runs commit `0cbfd93`, confirmed live
- **Live facility tests passed?**: YES — 8/8 (A–F matrix)
- **Blumax Auth DEV healthy?**: YES — unchanged, same persistent signing key
- **Labs/Auth integration passed?**: YES — delegated login, JWKS verification, local-role minting, no JIT provisioning, all confirmed live
- **Migration tool status**: DEV-proven only (56/56 real rows, idempotent); never run against production, by design
- **Identity continuity status**: Core→Blumax Auth→Labs and →Superadmin proven; →Pharmacy not implemented (pre-existing, out of scope)
- **Rollback status**: Config-only (`AUTH_PROVIDER=core`, already the live default everywhere); container-level rollback documented via re-export/rebuild from `2e260e0`, not exercised (not needed)
- **Total tests**: 765 (full Labs suite) + 12 (facility-scope) + 8 (live HTTP) = all passing
- **Blockers remaining**: Pharmacy identity continuity (pre-existing, out of scope); migration tool not production-proven (expected, by design) — neither blocks the DEV-only objective this phase closed
- **Exact next phase**: A separately authorized phase to (a) design Pharmacy's identity-continuity mechanism if a platform-wide cutover is ever wanted, and/or (b) a dedicated production-readiness phase — neither started here, per explicit instruction
