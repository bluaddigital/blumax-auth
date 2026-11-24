# Changelog

Started with 0.5.2; earlier releases are described in their tag commits (`git log v0.5.1`).

## 0.6.0 (proposed; unreleased, no tag: the owner tags it. Contains everything in 0.5.2.)

Role map for permission checks, **OFF by default** (`configure_permissions(role_map=...)`, or env `BLUMAX_PERMISSION_ROLE_MAP=true`
when the argument is left at None). With it off, behaviour is 0.5.2's exactly.

- `AuthContext` gains `role_ids` (token claim `rid`) and `roles_version` (claim `pv`), both None unless the token carries both,
  well-formed. Only the permission checker reads them.
- When on, and the token carries both, and `configure_session_revocation()` gave this process the shared Redis: the session is
  checked against the revocation markers, the tenant's published versions are read (`ZMSCORE role:perms:ver <tenant> grants`,
  reused <= 5 s), and when the token's `pv` equals the tenant's, the codes come from a per-process role -> codes map fetched once
  per grants version from Core's `GET /api/v1/identity/role-permissions` (caller's own token, If-None-Match). Anything else falls
  back to the 0.5.2 path (`GET /api/v1/me/permissions`); never a grant on doubt. See "Role map" in `permissions.py`.
- Counter outcomes `role_map_hit`, `role_map_fallback`, `role_map_fetch`.
- Needs Core with `PERMISSION_VERSION_CLAIMS_ENABLED=true` (blumax-backend migration 231 + the claims / publisher / endpoint).
  Rollout: [docs/ROLE_MAP_ROLLOUT.md](docs/ROLE_MAP_ROLLOUT.md).

## 0.5.2 (unreleased: no tag yet, the owner tags it)

Permission client (`require_permission`, `check_permission`), containment layers C1-C4 of
blumax-platform `docs/architecture/service-dependency-map.md`:

- **C2 circuit breaker** (APP-007, PR #12): after 5 consecutive Core failures (no answer, 5xx,
  malformed) lookups are refused at once for 10 s, same fail-closed 503. `breaker_failures=0`
  turns it off. HTTP keep-alive 3 s, below uvicorn's 5 s (APP-006).
- **C3 retry once on no answer** (IMP-DEP-4): `retry_on_no_answer=True` (default),
  `retry_pause_seconds=0.15`. Only after a timeout or connection error; never after Core answered
  (401/403/404/5xx/malformed), never while the breaker is open. Shared by concurrent waiters
  (inside the single-flight fetch). Worst case for one check: 2 x timeout + pause.
  Same rules as IPD's / OPD's local `app/core/permission_resilience.py`.
  **If a service still installs that local wrapper, set its `PERMISSION_CHECK_RETRY=false` (or
  drop the wrapper) when it moves to 0.5.2, otherwise a no-answer lookup is asked up to 4 times.**
- **C4 bounded stale-on-error** (IMP-DEP-5): `stale_grace_seconds=0` (default, OFF), clamped to
  120. When on: during an outage (no answer, 5xx, breaker open) this process's last successful
  answer for the same tenant + user + token hash is reused up to the grace past its TTL. Never
  without a prior success, never after Core answered 401/403/404 for that key, never on a
  malformed answer, never on routes marked `require_permission(code, admin=True)` /
  `check_permission(..., admin=True)`. Every serve logs `permission_check_served_stale` (WARNING)
  and counts `stale_served`. Session revocation and token expiry still apply. Enabling it is an
  owner decision per service (OD-DEP-1); services pass `PERMISSION_CHECK_STALE_GRACE_SECONDS`.
- **O9 counter** `blumax_core_permission_calls_total{outcome}` (outcomes: ok, unauthorized,
  forbidden, server_error, malformed, timeout, unreachable, breaker_open, retried, stale_served).
  Registered in prometheus_client's default registry only when `BLUMAX_METRICS_ENABLED=true`;
  prometheus_client is optional (`pip install blumax-auth[metrics]`), missing -> one warning.
- `blumax_auth.__version__`.

Tests only (SEC-09 / SEC-10, no library change): `tests/test_revocation_matrix.py`, the executable expiry / revocation matrix run once per
consuming service's real wiring (15 profiles), with the Redis down / hung / flushed / evicted / restarted rows and their documented
expectations; opt-in real-Redis container tests (`BLUMAX_AUTH_TEST_REDIS_CONTAINER=1`) and a wiring check against the sibling repositories
(`BLUMAX_CONSUMERS_ROOT`). It pins the residual window (a flushed or evicted marker re-validates a revoked session in `open` AND `closed`)
and the services that verify tokens but never check revocation (DIS, CDSS, WA service, Composer).

JWKS (APP-005, PR #12): after the TTL with Core unreachable a held key is served at once inside
the unchanged 24 h stale bound; one caller refreshes; a failed refresh backs off 10 s.
