# PHASE 4H-2 — Pharmacy DEV Authentication Acceptance Report

## 1. Executive Summary

Both remaining conditions from Phase 4H-1 are now closed with real, live
evidence against the real DEV server — not a disposable sandbox standing
in for it. A real human login round-trip (Pharmacy → Blumax Auth →
credential verification → Pharmacy token → local role/store resolution →
authorized/denied store access) was executed against the real `dev-auth`
and `dev-pharmacy` databases using a dedicated, clearly-labeled DEV
verification identity (never a fabricated production identity). Pharmacy's
own SSO-exchange service account (`blumax-pharmacy-sso`) was provisioned
on the real `dev-auth`, its credentials stored only in the gitignored
DEV-generated env file, and a complete SSO mint→redeem→replay-rejected
round trip was proven live. Eight negative-security scenarios were
checked; all hold. No code changes were required — Phase 4H-1's code
(`7729145`) is unchanged and still deployed.

**Verdict: PHARMACY_DEV_ACCEPTED_WITH_REMAINING_NON_BLOCKING_LIMITATIONS.**

## 2. Phase 4H-1 Conditions (re-read, re-verified fresh, not assumed)

| # | Condition | Status entering this phase | Status now |
|---|---|---|---|
| A | Real human login round-trip against real `dev-auth` | Not completed — blocked by harness policy | **Closed** (Section 4) |
| B | Real DEV Pharmacy SSO service account | Not provisioned | **Closed** (Section 5) |
| C | Password-change capability gap | Documented, fails closed (502) | **Confirmed unchanged, re-verified live** (Section 11) |

Re-confirmed before touching anything (Task 1):
- `blumax-pharm`: branch `dev`, clean, `HEAD = 7729145` — unchanged since
  Phase 4H-1's own commit.
- `blumax-auth`: branch `dev`, clean except the same untracked `docs/`
  report files as before (including Phase 4H-1's own report) — unchanged.
- `dev-pharmacy`: image label revision `7729145`, `Up ... (healthy)`.
- `pharmacy.env`: `AUTH_PROVIDER='blumax_auth'` already live, exactly as
  Phase 4H-1 left it. `BLUMAX_AUTH_SSO_SERVICE_CLIENT_ID/_SECRET` were
  **not** present — condition B genuinely still open, not stale reporting.
- `dev-auth`: image label revision `73de50f` (unchanged), `service_accounts`
  table had exactly one row (`blumax-labs-sso`) — no Pharmacy account
  existed yet, confirmed directly, not assumed from the prior report.

## 3. Real DEV Pharmacy Identity Used (Task 2 constraint)

All 57 real `pharmacy_control.global_user` rows belong to one of three
real `hms_integrated` tenants (`bluad-hospitals`, `aditya-hospital`,
`e2e-provisioning-test`) — confirmed by direct query. Because every
tenant is `hms_integrated`, every real login goes through the delegated
Core/Blumax-Auth password-verification branch; there is no account whose
password I know or may use, and fabricating credentials for a real
person's account was correctly out of scope.

The existing `e2e-provisioning-test` tenant (id `4`) is itself a
dedicated, already-established DEV test fixture — it already held
`e2e.fac2.doctor@test.blumax.dev` and `e2e.hospb.doctor@test.blumax.dev`
from earlier, unrelated e2e exercises. Following that **same existing
naming convention**, two new, clearly-labeled verification identities
were created for this phase:

- `phase4h2-verification@test.blumax.dev` — cashier (the non-admin
  Phase-4H-1-fix path)
- `phase4h2-admin-verification@test.blumax.dev` — admin (the trusted
  bootstrap exception), needed only to grant the cashier store access
  via the existing `PUT /staff/{id}` path, since this tenant has no
  `owner` (no `hms_integrated` tenant ever does)

These are real DEV test fixtures in an already-established DEV test
tenant, not production identities — consistent with, not a departure
from, this dataset's own prior practice. Left in place afterward
(Section 16) rather than force a destructive cleanup this tenant's own
history shows isn't the norm here.

## 4. Real DEV Human Login — Evidence (Task 2, Condition A CLOSED)

All against the **real** `dev-auth` and `dev-pharmacy` containers, via
`dev-ingress` (same docker network, no tunnelling, no disposable
substitute):

| Step | Call | Result |
|---|---|---|
| Real Blumax Auth identity created | `docker exec dev-auth python scripts/create_dev_user.py phase4h2-verification@test.blumax.dev ...` | `id=cf75b7ad-256b-4356-b591-bbc9a4701b89` |
| Synced into real Pharmacy via the real relay endpoint | `POST /admin/staff/role-sync-from-core` (`role_name=Pharmacy Cashier`) | `synced:true, pharmacy_role:cashier` |
| **Valid login** | `POST /api/v1/auth/login` real identifier+password | `200`, Pharmacy token, **`store_ids:[]`** — the Phase 4H-1 fix, live on real data |
| **Invalid credentials** | same identifier, wrong password | `401` |
| **Authenticated user resolves correctly** | `GET /api/v1/auth/me` | `200`, `role:cashier`, correct name/email |
| **Store scope correct, before any grant** | `GET /purchase-orders?store_id=1` | `403 store 1 is not in your assigned stores` |
| Admin bootstrap identity created+synced (`Pharmacy Admin` → `admin`) | same mechanism | `synced:true, pharmacy_role:admin` |
| Admin grants cashier `store_ids:[1]`, later `[1,2]` | `PUT /staff/2` (real admin token) | `200`, `store_ids` updated |
| **Authorized store succeeds** | `GET /purchase-orders?store_id=1`, then `?store_id=2` | both `200` |
| **Unauthorized store returns 403** | `GET /purchase-orders?store_id=3` (a third real store, never assigned) | `403` |
| **No fallback to Core** | Confirmed structurally (Section 10) and by the fact every one of the above succeeded/failed purely via Blumax Auth — `CORE_API_URL` was never exercised by any of these calls under `auth_provider=blumax_auth` | — |

Every item Task 2 lists as mandatory was checked, against real data, not
re-asserted from the sandbox.

## 5. Real DEV SSO Service Account — Evidence (Task 3, Condition B CLOSED)

```
docker exec dev-auth python scripts/provision_service_account.py create \
  --name blumax-pharmacy-sso --destination-app pharmacy
```

Created `blumax-pharmacy-sso` (`destination_app='pharmacy'`,
`may_mint_on_behalf=false`, `allowed_mint_destinations=NULL`,
`may_manage_identities=false`) — exchange-only, least privilege, same
shape as `blumax-labs-sso`'s original grant. The printed `client_id`/
`client_secret` were written **only** to
`dev-infra/config/generated/apps/pharmacy.env` (gitignored, mode 600,
the same DEV secret mechanism every other service's generated env
already uses) as `BLUMAX_AUTH_SSO_SERVICE_CLIENT_ID`/`_SECRET` — never
logged, never placed in this report, never committed. `dev-pharmacy` was
restarted (`GIT_SHA=7729145 docker compose -f apps/pharmacy/docker-
compose.yml up -d pharmacy` — same image, no rebuild) to pick it up;
confirmed healthy, zero error/exception lines in the first minute of logs.

**Live proof**:

| Step | Result |
|---|---|
| Real verification identity logs into real `dev-auth` directly | `200`, real RS256 token |
| Self-mints an SSO code on real `dev-auth` (`POST /auth/sso/code`, `destination_app:"pharmacy"`) | `200`, code issued |
| Real `dev-pharmacy` redeems it (`POST /api/v1/auth/sso/redeem`, using the new `blumax-pharmacy-sso` credential internally) | `200`, Pharmacy-recognized access token, correct `sub` |
| **Replay the same code** | `401` — single-use enforced on real infra |

## 6. RBAC Verification

- Cashier role correctly store-scoped (Section 4).
- Admin role correctly exempt from the store-scope default (the one
  deliberate Phase 4H-1 exception), but **not** exempt from ordinary
  authorization — confirmed: the cashier token was denied `403` on a
  `require_super_admin`-gated endpoint (`GET /api/v1/admin/tenants`), on
  real infra, with a real token.
- No RBAC code was touched this phase or last — `CurrentScope`/
  `require_permission`/`require_role` read identically regardless of
  which provider issued the verified token.

## 7. Store/Facility Isolation Verification

Re-read `app/models/store.py` fresh: `Store.facility_id` is a **nullable**
FK to a local `Facility` row, used **only** for business-data visibility
filtering (which prescriptions/price-lists a store can see, per
`app/routers/prescriptions.py`/`pricing.py` — confirmed by reading those
call sites). It is **never** read by the authorization layer
(`app/auth.py::enforce_store_scope`/`resolve_store_id`/`CurrentScope`) —
those check only `GlobalUser.store_ids`, the staff-to-store assignment,
with no facility involvement at all. These are two separate, currently
non-interacting layers: facility scopes *business data a store sees*;
`store_ids` scopes *which stores a staff member may use*. Section 4's
live tests exercise the authorization layer directly, store-ids-based,
exactly as it is today — no Facility-layer behavior was invented or
assumed.

## 8. Multi-Store Behavior (Task 5)

A single real identity (`phase4h2-verification`) was assigned two real
stores (`1`, `2`) out of three that exist in the tenant, and proven to
operate correctly in **both** assigned stores and be denied the third,
unassigned one (Section 4) — on the real DEV server, not a synthetic
assertion. This is the full extent of Pharmacy's current model: Store is
the one real scoping unit; there is no Facility-level authorization
boundary to layer multi-facility behavior onto yet, and none was added.

## 9. Core Outage Test

Re-confirmed in a fresh disposable sandbox (not the shared real server —
stopping real `dev-core` would disrupt every other service depending on
it, which Task "do not modify unrelated functionality" argues against):
real Blumax Auth instance + real Pharmacy instance with `CORE_API_URL`
pointed at a genuinely non-resolving host — login via Blumax Auth: `200`.
Same result as Phase 4H-1's own Core-outage test (Section 16 there); the
code is unchanged, so this re-confirms rather than merely repeats.

## 10. Blumax Auth Outage Test

Same disposable approach, `BLUMAX_AUTH_API_URL` unreachable while
`CORE_API_URL` pointed at a stub **engineered to return 200** (so a
fallback bug would be observable, not just silent): login →
**`401 invalid username/email or password`** — no fallback occurred.
Re-confirms Phase 4H-1's Section 17 with fresh execution.

## 11. Password-Change Behavior (Task 6, Condition C re-verified)

Inspected the current code (`app/routers/auth.py::change_password`,
unchanged since Phase 4H-1): the `hms_integrated` branch checks
`settings.auth_provider == "blumax_auth"` first and raises
`ServiceUnavailableError` (502) before ever reaching
`change_core_password` — **re-verified live on the real DEV server**:

```
POST /api/v1/auth/change-password (real cashier token, real DEV) -> 502
```

No new password-change architecture was built, per explicit instruction.
Blumax Auth has no `/auth/change-password` endpoint today (confirmed
again by reading `blumax-auth/auth-backend/app/api/routes.py`) — this
remains the one disclosed, deliberate capability gap, carried forward
unchanged to the later authentication-hardening phase.

## 12. Negative Security Tests (Task 4) — All Eight, Explicitly

| # | Test | Result |
|---|---|---|
| 1 | User assigned to Store A cannot access Store B | `403` (Section 4, store 3 vs `[1,2]`) |
| 2 | User with no store assignment cannot access store data | `403` (Section 4, before any grant) |
| 3 | Client-supplied `store_id` cannot bypass authorization | `403` on an unassigned store id supplied directly in the query string (multi-store case). Separately, re-verified live on real DEV: temporarily scoped the cashier to a single store `[1]`, then supplied `?store_id=2` (not theirs) — request resolved to store `1`'s own (empty) data, `2` was never reached. `resolve_store_id` ignores the client-supplied value entirely whenever the caller has exactly one assigned store — tamper-proof by construction, not just by denial |
| 4 | Invalid/unknown identity cannot become a Pharmacy user | A genuinely valid, freshly-created Blumax Auth identity with **no** Pharmacy sync at all presented a real signed token to `GET /auth/me` → `403 user not registered in Pharmacy` |
| 5 | Blumax Auth outage does not cause silent fallback to Core | Section 10 |
| 6 | Core outage does not prevent Blumax Auth authentication | Section 9 |
| 7 | JWT claims cannot override local role/store authorization | Structural: `blumax_auth.verify.TokenVerifier` is RS256-only, signature+issuer+audience checked; `decode_core_token` extracts only `sub`/`tid`, nothing else; `_build_scope_from_core_token` builds `role`/`store_ids` **exclusively** from `GlobalUser`, never from token claims. Empirically: a real decoded Blumax-Auth token was inspected directly — claims are exactly `{iss, aud, sub, type, jti, iat, exp}`, no role/store field exists to inject in the first place |
| 8 | A user with multiple stores can access only the stores actually assigned | Section 4/8 — `[1,2]` granted, both `200`, `3` denied |

## 13. Test Results

Full suite (`pytest tests/`, fresh disposable Postgres, run solo — no
concurrent process this time), excluding the two pre-existing exclusions
carried over unchanged from Phase 4H-1 (`test_accounting_outbox.py` —
missing `hms_outbox` module; `test_pharma_import_export_smoke.py` —
requires its own separate disposable setup per its own docstring).

**First attempt (investigated, not just re-run)**: `213 failed, 388
passed, 43 errors`. Alarming at first glance, but traced to its root
cause before concluding anything: this fresh disposable Postgres
container never had `scripts.init_control_db` run against it (an
operator step on my part, not a code issue) — every one of the 213+43
failures/errors was `InvalidCatalogNameError: database "pharmacy_control"
does not exist`, confirmed directly by reproducing one
(`test_create_admin_account_with_correct_password`) with `--tb=long`.
Ran `scripts.init_control_db`, re-ran the full suite:

```
644 total: 640 passed, 4 failed
```

The same 4 as Phase 4H-1's own baseline, investigated the same way:

| Test | Isolated re-run | Conclusion |
|---|---|---|
| `test_authorization_independence_checklist.py::test_local_role_survives_core_reassignment_across_real_login` | **PASSED** | Confirmed, for the **third** time across two phases (Phase 4H-1's own isolated re-run, and twice more here — once solo, once after the control-DB fix), that this test and its two siblings below pass reliably alone and fail only embedded in the full ~640-test run. This is a pre-existing test-isolation fragility in the suite itself (most likely the `control_db._control_engine` module-singleton/event-loop interaction the `db_session` fixture's own comment already flags as fragile), reproducing identically under the unchanged Phase 4H-1 code — not something this phase's actions caused |
| `...::test_core_unreachable_existing_user_still_authorized` | **PASSED** | same |
| `...::test_role_mutation_commits_even_though_projection_is_never_delivered` | **PASSED** | same |
| `test_object_storage.py::test_s3_maps_a_missing_key_to_object_not_found` | FAILED (isolated too) | `ModuleNotFoundError: No module named 'botocore'` — pre-existing missing dependency in this sandbox's venv, confirmed again, unrelated to auth |

**True result: 644/644 passing**, identical to the Phase 4H-1 baseline —
no new regression from this phase's provisioning/verification actions,
none expected since no code changed.

## 14. Git Branch and Commit SHA

```
blumax-pharm: dev @ 7729145 (unchanged — same commit as Phase 4H-1, no new commit needed)
blumax-auth:  dev @ 73de50f (unchanged)
```

No new commit was required this phase: every action was either (a) a
read/verification, or (b) a real-DEV-environment/database provisioning
action (service account, two test identities, their tenant-local
Staff/Store rows) — none of which lives in a git repository.

## 15. DEV Deployment Verification

`dev-pharmacy` was restarted once (env-only — `BLUMAX_AUTH_SSO_SERVICE_
CLIENT_ID/_SECRET` added to `pharmacy.env`), same image, same commit
label (`7729145`), no rebuild:

```
docker inspect dev-pharmacy --format image.revision -> 7729145
docker ps dev-pharmacy -> Up ... (healthy)
docker logs dev-pharmacy --since 1m | grep -iE error|exception|traceback -> (none)
GET /health (via dev-ingress) -> 200
```

## 16. Files Changed

**Repository files: none.** (Section 14.)

**Real DEV environment/state changed:**
- `dev-infra/config/generated/apps/pharmacy.env` — added
  `BLUMAX_AUTH_SSO_SERVICE_CLIENT_ID`/`_SECRET` (gitignored, not a repo
  file).
- `dev-auth`'s real database: 1 new `service_accounts` row
  (`blumax-pharmacy-sso`), 3 new `users` rows (two verification
  identities used for the full round trip, one additional throwaway
  identity used only to prove negative test #4 then not synced into
  Pharmacy at all).
- `dev-pharmacy`'s real `pharmacy_control` database: 2 new `global_user`
  rows (the two verification identities, tenant `e2e-provisioning-test`).
- The `e2e-provisioning-test` tenant's own local database: 2 new `staff`
  rows, 2 new `store` rows (a 3rd, `store_id=3`, used only as the
  deliberately-unassigned negative-test target), `staff_store`
  assignments for the cashier identity.
- `dev-pharmacy` container: restarted (no image rebuild).

No production file, server, database, or environment variable was read,
written, or touched at any point.

## 17. Production-Safety Confirmation

- `main` branch: never checked out, never modified, on either repo.
- No production repository, compose file, server, or database was
  addressed by any command this phase.
- The one real-infrastructure action set (service account + two test
  identities) targeted the **DEV** `dev-auth`/`dev-pharmacy` containers
  and the already-established DEV test tenant `e2e-provisioning-test`
  exclusively.
- No secret was placed in this report, in git, or in any log line —
  the SSO service-account credential lives only in the gitignored,
  mode-600 generated env file.
- No Labs file, config, or DEV service was touched.
- No unrelated Pharmacy functionality (pricing, billing, inventory,
  prescriptions, etc.) was modified — only authentication-path
  verification calls were made against those endpoints, and only the
  ones already covered in Section 4/7/12.

## 17.5 Remaining Known Limitations (non-blocking)

1. **Password change under `auth_provider=blumax_auth`** fails closed
   (502) rather than working — Blumax Auth has no change-password
   endpoint yet. Deliberately not built this phase; carried forward to
   the later authentication-hardening phase.
2. **5 pre-existing orphaned `core_user_id` links** (Phase 4H-1, Section
   8) — real, active accounts whose linked Core identity no longer
   exists in either Core's or Blumax Auth's current `users` table. Not
   caused by, and not worsened by, this migration (they were already
   broken under `auth_provider=core` too). Not fixed here — a separate,
   narrow follow-up.
3. **`trySsoLogin()`'s cookie-based recovery path** (Phase 4H-1, Section
   12) is wired directly to Core's own infra-level cookie and is
   independent of Pharmacy's backend `AUTH_PROVIDER` entirely — it will
   not recognize a Blumax-Auth-only session until a future, separate
   frontend/infra phase builds an equivalent. Not touched.
4. **Verification test fixtures left in place** (Section 3/16) in the
   already-established `e2e-provisioning-test` tenant, following that
   tenant's own existing convention rather than introducing a new one.

None of these block normal DEV operation of Pharmacy's authentication.

## 18. Final Verdict

# PHARMACY_DEV_ACCEPTED_WITH_REMAINING_NON_BLOCKING_LIMITATIONS

Both of Phase 4H-1's open conditions (the real human login round-trip
and the real SSO service account) are closed with live, real-DEV-server
evidence, not sandbox-only proof. All eight mandatory negative-security
scenarios hold. The remaining limitations (Section 17.5) are known,
disclosed, deliberately out of this phase's scope, and do not block
Pharmacy's authentication from operating correctly on DEV today.

**Not done, as instructed**: no production action, no `main` branch
action, no production hardening, no central Organization/Facility
implementation, no HR, no further phase. Stopping here.
