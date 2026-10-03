# Blumax Auth Migration

## Status: Phase 1 complete (built, tested, not consumed by anything)

Core remains the production authentication authority. Nothing described
here has been deployed, and no production application has been
repointed at this service. `blumax-auth`'s own verification package
(`src/blumax_auth`, pip package `blumax-auth`) is unchanged and still
verifies Core-issued tokens exactly as before.

## Why this exists

The target architecture separates identity/authentication (Blumax Auth)
from each application's own local authorization (Superadmin/Core/
Pharmacy/Labs each keep their own roles/permissions). Before any real
cutover, Blumax Auth needs to exist as a real, independently-deployable
service and be proven compatible with the verification rules every
application already uses -- without touching any of those applications.
This phase is that proof.

## The "token scope" decision (made explicitly, not assumed)

Core's current access tokens carry business claims (`tid`, `rol`, `arc`,
`fac`, `pid`, `prv`, `adm`) built at login time from the user's tenant
membership -- data that belongs to Core, not to an identity service.
Blumax Auth cannot mint those claims without either holding a copy of
tenant-membership data itself (blurring the "no business data in Auth"
line) or deferring full-claim compatibility to a later phase.

**Decision: Phase 1 issues a deliberately THIN token** -- `iss`, `aud`,
`sub`, `type`, `jti`, `iat`, `exp` only. No tenant/role/facility claims.

This is backed by a real property of the existing verification code, not
just an assumption: `blumax_auth`'s own `TokenVerifier._to_context`
(`src/blumax_auth/verify.py`) already defaults every business claim to
its most restrictive interpretation when absent (`archetype` →
`"VIEWER"`, `tenant_id`/`role`/`facility_ids`/`person_id`/`provider_id`
→ `None`, `is_platform_admin` → `False`) -- it was written to tolerate a
token that predates these claims. `tests/test_backward_compat.py::
test_thin_token_with_no_business_claims_degrades_safely_not_crashes`
proves this against the real package, not a mock.

Full-claim parity (Blumax Auth producing a byte-identical token to
Core's current one) becomes a Phase 6 problem, once Core itself is the
one calling Blumax Auth to mint tokens and can supply the business
claims from its own data at that point -- not before.

## What exists now

- A standalone FastAPI service (`app/`), own database (`users`,
  `refresh_tokens`), own Redis-backed rate limiting and session
  revocation, own Alembic migrations.
- RS256 signing with the exact same key-rotation mechanism as Core's own
  `app/core/keys.py` (deterministic `kid`, `JWT_PREVIOUS_PUBLIC_KEY`
  dual-key window) -- not reinvented, so the eventual real key transplant
  (Phase 6) is a key-material swap, not a code change.
- Two security fixes identified in the prior Core audit, addressed here
  (not retrofitted into Core, which stays untouched per the "no
  production breakage" rule):
  - **Timing-safe login** (`app/core/security.py::
    verify_password_constant_time`) -- always pays the bcrypt cost,
    dummy hash or real, closing the side-channel that let a nonexistent
    identifier be distinguished from a wrong password by response time.
  - **Explicit, observable session-revocation fail-mode**
    (`app/core/session_revocation.py`, `SESSION_REVOCATION_FAIL_MODE`,
    default `"closed"`) -- a Redis outage no longer silently re-honors a
    logged-out user's still-unexpired access token; the choice is
    configurable and always logged loudly either way.
- 32 passing tests (`pytest`, run against a disposable Postgres+Redis
  pair, never touching any shared/production instance) covering login,
  JWT validation (including alg-confusion and alg=none attacks, hand-
  built since `python-jose`'s own `encode()` refuses to construct them),
  refresh rotation + reuse detection, session revocation, JWKS
  (including a simulated rotation window), and the backward-compatibility
  proof above.

## What does NOT exist yet (deliberately)

- Full-claim token issuance (tenant/role/facility) -- Phase 6, see above.
- Any consumer repointed at this service -- Superadmin, Core, Pharmacy,
  Labs all still use Core for issuance/verification exactly as before.
- Password migration execution (see below -- mechanism is documented,
  not run).
- MFA, account-level lockout (only IP-rate-limiting exists, matching
  Core's own current scope), security-headers middleware -- none of
  these exist in Core today either; not invented here beyond parity.

## Password migration

Core's bcrypt hashing scheme (`passlib`, `CryptContext(schemes=
["bcrypt"])`) is replicated exactly in this service. A `users.
hashed_password` column migrated verbatim from Core's own `users` table
would verify unchanged -- **no forced password reset required**. This
phase does not execute that migration; it only confirms the mechanism is
compatible (same hashing library, same hash format).

## Signing key strategy

- **Now**: a separate, Phase-1-only dev key (`JWT_DEV_KEY_PATH`,
  generated once, cached locally, `chmod 0o600`) -- never Core's real
  key, never touches production.
- **Phase 6 (the real cutover)**: transplant Core's actual production
  private key into this service's `JWT_PRIVATE_KEY`. Same key → same
  `kid` → every existing consumer's cached JWKS entry still matches, so
  this step alone is invisible to consumers. The dual-key rotation
  mechanism (`JWT_PREVIOUS_PUBLIC_KEY`) is what then allows a *later*,
  separate, deliberate key rotation if/when desired -- not required for
  the service-cutover itself.

## API surface: Core today vs. Blumax Auth (Phase 1)

| Core (production, unchanged) | Blumax Auth (Phase 1, dark) |
|---|---|
| `POST /auth/login` → full claims | `POST /auth/login` → thin claims |
| `POST /auth/refresh` | `POST /auth/refresh` (same rotation/reuse-detection shape) |
| `POST /auth/logout` | `POST /auth/logout` |
| `GET /.well-known/jwks.json` | `GET /.well-known/jwks.json` (same JWK shape) |
| `GET /auth/me` (not Core's actual route name, for illustration) | `GET /auth/me` (thin claims only) |
| `POST /auth/service-token` | not built in Phase 1 -- service-account/machine auth is a named, deferred scope, not silently dropped |

No production consumer's request/response contract changes as a result
of this phase existing.

## Migration sequence

**PHASE 1 (this phase, complete)**: build Blumax Auth independently,
dark, with a thin token and a proven-compatible claim shape.

**PHASE 2**: expand the backward-compatibility test suite against a
copy of each real consumer's own verification configuration (not just
the shared library in isolation) -- still no consumer touched.

**PHASE 3**: migrate Superadmin -- lowest risk, already confirmed
(earlier audit) to depend on nothing but a JWKS URL.

**PHASE 4**: migrate Labs -- confirmed to have no login-time Core
dependency at all today.

**PHASE 5**: migrate Pharmacy -- requires resolving the `hms_integrated`
password-verification bridge first (a Pharmacy-side, not Auth-side,
decision already scoped in an earlier audit).

**PHASE 6**: migrate Core -- transplant the real signing key, dual-issuer
window, add full-claim issuance (tenant/role/facility) once Core is the
one supplying that data to Blumax Auth at mint time.

**PHASE 7**: retire Core's own issuance code, only after a defined
stable observation window with zero fallback invocations.

Phases 3-7 are not executed by this document -- this is the plan only,
per the explicit instruction not to run ahead of approval.
