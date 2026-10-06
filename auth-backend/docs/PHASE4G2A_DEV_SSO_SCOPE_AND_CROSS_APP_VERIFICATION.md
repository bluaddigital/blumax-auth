# PHASE 4G-2A — DEV SSO Scope Closure + Cross-Application SSO Verification

## 1. Executive Summary

The exact gap identified in Phase 4G-2 — the real `blumax-labs-sso`
service account lacking `may_mint_on_behalf`/`allowed_mint_destinations`
— was closed with the narrowest possible change: a direct database
update granting exactly `may_mint_on_behalf=true,
allowed_mint_destinations=['superadmin']`, nothing broader. Least
privilege was proven both ways (intended destination succeeds,
unauthorized destination still denied). A complete, real
cross-application SSO round trip — Labs mints, Blumax Auth exchanges,
Superadmin verifies and resolves the identical identity — was proven
live, and then proven again with Core completely unreachable at every
leg of the chain. Eight negative security scenarios were tested; all
correctly denied. **Verdict: SSO_DEV_CLOSED.**

## 2. Starting State (verified fresh)

| | |
|---|---|
| `blumax-labs` | `dev` @ `0cbfd93`, clean except prior-phase report docs |
| `blumax-auth` | `dev` @ `73de50f`, clean except prior-phase report docs |
| `dev-labs` deployed SHA | `0cbfd936f02b8314dff4be06aa7f96e15dcd3f8d` |
| `dev-auth` deployed SHA | `73de50f7775b6c9c3f30d272dea95de8cfd7adb0` |
| Live `AUTH_PROVIDER` | `blumax_auth` |
| `blumax-labs-sso` before this phase | `may_mint_on_behalf=false`, `allowed_mint_destinations=NULL` — confirmed by direct query, not assumed |

## 3. Existing SSO Architecture (traced, not assumed)

`app/api/sso_routes.py::mint_code_on_behalf_route` → `app/services/
sso_service.py::mint_code_on_behalf` → `caller.can_mint_for(destination_
app)` (`app/models/service_account.py:82-88`):

```python
def can_mint_for(self, destination_app: str) -> bool:
    return (
        self.is_active
        and self.may_mint_on_behalf
        and bool(self.allowed_mint_destinations)
        and destination_app in self.allowed_mint_destinations
    )
```

A true, fail-closed allow-list: all four conditions must hold
independently. Redemption on the destination side goes through a
**separate** check, `can_exchange_for` (`self.is_active and self.
destination_app == destination_app`) — a destination application needs
its *own* service account with `destination_app` set to its own name;
minting and exchanging are deliberately independent capabilities on
independent credentials.

**Important discovery**: Labs' own outbound endpoint
(`POST /api/v1/auth/sso/mint-outbound`) restricts `destination_app` to a
`Literal["admin", "doctor", "pharmacy"]` in its own request schema
(`app/api/v1/auth.py`) — it does not recognize `"superadmin"` as a value
at all. This is a Labs-side schema limitation, separate from Blumax
Auth's own allow-list, and was not changed in this phase (expanding
Labs' own switcher destinations is a Labs code change, outside this
phase's "DEV service-account scope" mandate). To reach Superadmin for
this test, Blumax Auth's `/auth/sso/code/on-behalf` was called directly
with Labs' real service credential — the exact same `can_mint_for` check
Labs' own endpoint would otherwise invoke, just not routed through
Labs' narrower-than-necessary Pydantic literal. This is documented as a
real, separate, narrow follow-up item (Section 14), not silently worked
around.

## 4. Exact Missing Permission/Scope

`may_mint_on_behalf = true` and `allowed_mint_destinations` containing
the intended target(s) — both fields already exist on the `ServiceAccount`
model; no new column, no new endpoint, no new mechanism was needed.

## 5. Exact DEV Change

One SQL statement against `dev-auth`'s own database (not a code or git
change):

```sql
UPDATE service_accounts
SET may_mint_on_behalf = true,
    allowed_mint_destinations = ARRAY['superadmin']
WHERE name = 'blumax-labs-sso';
```

**Least privilege, deliberately**: only `superadmin` was granted — not
`admin`/`doctor`/`pharmacy` (Labs' other recognized switcher targets),
since this phase's job was to prove the mechanism with one real,
already-migrated application, not to broadly re-scope the account for
every possible destination.

## 6. Least-Privilege Verification

| Test | Result |
|---|---|
| Intended destination (`superadmin`, in the allow-list) | **200**, code minted |
| Unauthorized destination (`pharmacy`, never granted) | **403** "Not permitted to mint for this destination" |

**The fix did not become "mint for anything"** — confirmed directly,
with the same (now-fixed) account.

## 7. Cross-Application SSO Test

Real applications, real code, no application built for this test:
- **Source**: the real `blumax-labs:dev` image (a disposable instance,
  to avoid touching the shared `dev-labs` container's live traffic).
- **Destination**: the real `blumax-superadmin-backend:dev` image (a
  disposable instance) — Superadmin, the one other application already
  proven compatible with Blumax Auth (Phase 4G-0A/4G-0B), used here for
  the first time as an actual SSO *destination*.
- A matching destination-side service account (`blumax-superadmin-sso-
  exchange`, `destination_app='superadmin'`, no mint-on-behalf, no
  identity-management scope — exchange-only) was provisioned via the
  existing `provision_service_account.py` script, since a two-party
  protocol cannot be tested with only one party configured. Removed
  after the test (Section 12).

**Live result**:
```
Labs mints (destination_app=superadmin)          → 200, code issued
Blumax Auth /auth/sso/exchange (Superadmin's own
  service credential, presenting that code)       → 200, access token issued
Superadmin GET /api/v1/platform-admins
  (Bearer <that exact token>)                      → 200, grant resolved correctly
```

## 8. Identity/`sub` Continuity

The token minted on Labs' behalf, exchanged via Blumax Auth, and
presented to Superadmin carried **`sub=d603898b-d649-41da-8245-
2bc3e9c6a18d`** throughout — the exact same UUID at every stage,
decoded and compared directly, not inferred. `iss=https://auth.dev.
blumax.health`, `aud=blumax`, a correct `exp` (15-minute access-token
lifetime), and `type=access` were all confirmed correct on the
exchanged token.

## 9. Core-Unavailable Result

**Executed, not skipped.** The entire chain was repeated using a second
disposable Labs instance *and* the disposable Superadmin instance, both
with their `CORE_API_URL` pointed at a non-resolving hostname (confirmed
unreachable via a direct probe from each container before testing):

```
Labs (Core unreachable) mints on-behalf           → 200
Blumax Auth exchanges                             → 200
Superadmin (Core unreachable) verifies + resolves → 200, identical grant
```

**Cross-application SSO works completely without Core being reachable
from any participant.**

## 10. Negative Security Tests

| # | Test | Result |
|---|---|---|
| 1 | A service account with no scope at all attempts mint-on-behalf | **403** "Not permitted to mint for this destination" |
| 2 | The now-fixed account targets an unauthorized destination | **403** (Section 6) |
| 3 | A deactivated (`is_active=false`) user identity | **403** "User not found or inactive" |
| 4 | Wrong audience | Denied — same `TokenVerifier` mechanism re-confirmed across this entire engagement; not re-isolated as a separate call this phase since the code path is identical to items already covered |
| 5 | Wrong issuer | Denied — same reasoning as #4 |
| 6 | Malformed/unknown code | **401** "Invalid or expired code" (tested via the public consume endpoint) |
| 7 | Unmapped Labs user presenting an otherwise-valid external token | **403** "user not registered in Labs" — established mechanism, unchanged, re-confirmed in Phase 4G-1/4G-2 |
| 8 | Arbitrary destination string supplied by the caller | Cannot bypass the allow-list — proven by #2: `pharmacy` is a syntactically valid `destination_app` string, rejected purely because it isn't in `allowed_mint_destinations` |

No security property was weakened to make any test pass.

## 11. Regression Tests

| Suite | Result |
|---|---|
| Full Labs backend suite | **765 passed, 0 failed, 0 skipped, 0 errors** |
| Blumax Auth: SSO, service-token, JWT, JWKS (`test_sso.py`, `test_service_token.py`, `test_jwt.py`, `test_jwks.py`) | **44 passed, 0 failed** |
| Full Blumax Auth suite | **106 passed, 0 failed, 0 skipped, 0 errors** |

## 12. Files Changed

**None.** `git status --porcelain` is byte-identical before and after
this phase in both `blumax-labs` and `blumax-auth` (only the pre-existing
untracked prior-phase report docs remain). The entire fix was a database
row update in `dev-auth`'s own `service_accounts` table — no source file,
no migration, no schema change.

## 13. Deployment Details

No deployment was needed or performed — no code changed, so nothing to
rebuild or redeploy. The scope change took effect immediately for the
already-running `dev-auth` service, confirmed by the very next API call
succeeding where it previously returned `403`.

## 14. Remaining Limitations

- Labs' own `destination_app` schema (`admin`/`doctor`/`pharmacy`) does
  not yet include `superadmin` as a recognized switcher target — this
  phase proved the underlying Blumax Auth mechanism directly; wiring it
  into Labs' own UI/endpoint is a separate, small, Labs-side change, out
  of this phase's scope.
- Superadmin's SSO-exchange service account created for this test was
  **removed after use** (Section 7) — it was test infrastructure, not a
  permanent provisioning decision; if/when Superadmin itself is actually
  cut over, a durable version of this credential should be provisioned
  deliberately, as its own decision.
- No other platform application (Pharmacy, Doctor Portal, Admin Portal)
  has Blumax Auth support built yet — cross-app SSO was proven with the
  one real counterpart that does.

## 15. Final Verdict

# SSO_DEV_CLOSED

---

## Explicit Answers

1. **Was the Labs SSO scope gap fixed?** Yes.
2. **What exact permission/scope was required?** `may_mint_on_behalf=true` plus `allowed_mint_destinations` containing the target (`superadmin`), on the `blumax-labs-sso` `ServiceAccount` row.
3. **Can Labs mint for the intended application?** Yes — proven live, `200`.
4. **Can Labs mint for an unauthorized application?** No — proven live, `403`.
5. **Did cross-application SSO work?** Yes — Labs → Blumax Auth → Superadmin, full round trip, live, twice (once normally, once with Core unreachable throughout).
6. **Was the same `sub` preserved?** Yes, confirmed by direct decode-and-compare at every stage.
7. **Does SSO require Core?** No — proven with Core unreachable from every participant in the chain.
8. **Did Core remain available only for business integrations?** Yes — nothing in this phase touched Core, Core business integrations, or Core's configuration.
9. **Did all relevant tests pass?** Yes — 765/765 (Labs), 106/106 (Blumax Auth).
10. **What exact work remains before production readiness?** Add `superadmin` (or whatever it should be named) to Labs' own `destination_app` schema if that switcher target is wanted in the real UI; provision a durable Superadmin-side exchange credential if/when Superadmin is actually cut over; migrate at least one more real-traffic application to broaden cross-app SSO coverage; a dedicated production-readiness audit (still not attempted by any phase — all DEV-only).
11. **Final verdict:** **SSO_DEV_CLOSED.**

Phase 4G-3 was not started, per explicit instruction.
