# Changelog

Started with 0.5.2; earlier releases are described in their tag commits (`git log v0.5.1`).

## Unreleased (next version after 0.5.2: no tag, no version bump; the owner tags)

Phase 0 security (JWT/SSO audit D-1, B2). Additive; every default is unchanged.

- **`fail_mode="split"` for session revocation** (env `SESSION_REVOCATION_FAIL_MODE=split`; the library default stays
  `"open"`, `"open"`/`"closed"` behave exactly as before). When the revocation store is unavailable in enforce mode:
  writes (anything but GET/HEAD/OPTIONS), routes marked sensitive and exports/credential changes FAIL CLOSED with
  `SessionRevocationUnavailable` (503 + `Retry-After`); safe reads keep using the last known status for at most
  `SESSION_REVOCATION_STALE_READ_SECONDS` (default 300, clamped to 3600) counted from this process's last SUCCESSFUL
  store check, then fail closed too. A session this process already saw revoked stays revoked. The 10 s breaker keeps
  its job but no longer lets writes through in split mode. Mark a route sensitive with
  `Depends(session_revocation_check(sensitive=True))` (order-independent) or by `require_permission(code, admin=True)`
  running earlier in the request (it sets `request.state.blumax_sensitive_route`).
- **Optional per-process session-status cache** `SESSION_STATUS_CACHE_SECONDS` (default 0 = off, exact old behaviour;
  2-5 recommended), `SESSION_STATUS_CACHE_MAX_ENTRIES` (10000): keyed by (user, iat, jti), bounded LRU, single-flight,
  expiry jittered 0-20 % short; "revoked" answers are kept 26 h; unavailable answers are never cached; sensitive routes
  bypass it. A revocation is visible within the TTL.
- **Counters** `blumax_session_revocation_total{outcome}` (Prometheus only when `BLUMAX_METRICS_ENABLED=true`) and
  `blumax_auth.metrics.session_snapshot()`: `cache_hit`, `cache_miss`, `store_reads`, `store_unavailable`,
  `stale_read_served`, `rejected_unavailable`, `revoked`. Rate-limited WARNING `revocation_store_unavailable` with
  outcome, fail_mode, method, sensitive, stale_age_seconds.
- `AuthError.headers` (optional response headers) and `install_error_handler` sends them; **a service with its own
  AuthError renderer must pass `exc.headers` through or the 503 loses `Retry-After`** (status and body are unaffected).
- New exports: `SessionRevocationUnavailable`, `session_revocation_check`. `check_session_revocation` gained an
  optional `request` parameter (injected by FastAPI; a direct call without it is treated as a write under split).

Wave 2 (authorization migration plan, owner decisions). Additive.

- **Status-cache freshness ceiling**: `SESSION_STATUS_CACHE_SECONDS` is clamped to 5 s (a larger value logs
  `session_status_cache_seconds_clamped` and 5 is used); 3 is the recommended value when enabled; default stays 0 (off).
  A session already seen revoked is refused (401) during any store outage or breaker window, in every `fail_mode`
  (previously only split's stale-read path did this); sensitive routes never use the cache and, under `split`, fail
  closed when a fresh status cannot be established. New helper `clamp_cache_seconds`.
- **auth-backend (standalone Blumax Auth, dormant)**: `/auth/refresh` also consults the Redis session marker
  (refresh row created at or before it is refused; follows `SESSION_REVOCATION_FAIL_MODE`); a `user.password_changed`
  sync event (bare user_id + hashed_password, or any event with a changed hash) revokes the user's refresh rows and
  writes the marker; `revoke_user_sessions` now logs `session_revocation.marker_write_failed` and returns False on a
  Redis failure after the DB commit instead of raising a 500 (DB rows are authoritative).

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
