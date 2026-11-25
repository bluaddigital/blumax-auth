# Changelog

Started with 0.5.2; earlier releases are described in their tag commits (`git log v0.5.1`).

## 0.6.4 (unreleased: no tag yet, the owner tags it)

G8: scoped service tokens + delegated identity. **No behaviour change for any token Core issues today**: both need Core
switches that default off (`SERVICE_TOKEN_SCOPES`, `TOKEN_EXCHANGE_ENABLED`). 0.6.3 is taken by the scoped authz
versions PR (#24); this release is built on 0.6.2 and rebases onto it (the only overlap is the version number and
`_evaluate`'s first lines vs #24's freshness block -- different hunks).

- **Local evaluation of scoped service tokens** (`local_mode` shadow/local only): a service token with `ver: 2` and a
  `perm` claim (Core `SERVICE_TOKEN_SCOPES=enforce`: the role's codes INTERSECT the account's scopes) is answered from
  the token exactly like a staff v2 token (same freshness and catalogue rules). A service token without `perm` (every
  token today, and any unscoped account) still falls back with reason `service_token` and asks Core.
- **`AuthContext.actor`** (`blumax_auth.Actor`: `service_account_id`, `service_name`) from the RFC 8693 `act` claim of
  a delegated token (Core `POST /auth/token-exchange`), and `AuthContext.is_delegated`. None for a user's own token
  and for service tokens. A malformed `act`, or `act` on a service token, is refused (InvalidToken).

## 0.6.3 (unreleased: no tag yet, the owner tags it)

Scoped "permissions changed" versions (on top of 0.6.2; 0.6.4 is taken by the G8 service-token PR #25).

**A token without the new claims is checked exactly as in 0.6.1** (one GET of the global `authctx:authz_ver`, same
cache, same reasons). `local_mode="off"` (the default) is unchanged: nothing is read.

- Core with `AUTHZ_VER_SCOPE=scoped` adds `authz_tv` (the tenant's version) and `authz_uv` (the user-in-tenant version)
  to access token v2. When a token carries them, local evaluation reads `authctx:authz_ver`,
  `authctx:authz_ver:t:{tid}` and `authctx:authz_ver:u:{tid}:{sub}` in ONE `MGET` and needs all three to equal the
  token's values. Cached per (tenant, user) for the same `authz_ver_cache_seconds` window (<= 5 s), one in-flight read
  per (tenant, user), at most 10 000 cached callers (expired first, then oldest).
- An ABSENT tenant / user key never matches (Core creates both before minting, so absent = evicted / flushed). The
  values are opaque non-repeating strings, compared with `!=`.
- Reasons unchanged: mismatch at any level -> `authz_ver_stale`, now with `authz_stale_scope` = `global` | `tenant` |
  `user` in the log line (text and `extra`) and on `LocalDecision`; global key absent -> `authz_ver_unset`; Redis
  error / timeout / short reply -> `authz_ver_unavailable`; only one of the two claims, or a non-string / empty one ->
  `no_authz_ver`. Never a local grant on doubt.
- The Redis user needs `MGET` on `authctx:authz_ver:*` (the same key family as before).
- **Rollout: every service on >= 0.6.3 BEFORE Core switches to `scoped`.** An older library ignores the new claims and
  compares the global key alone, which Core no longer bumps for tenant / user changes in scoped mode.
## 0.6.2 (unreleased: no tag yet, the owner tags it)

Phase 5b: per-session access revocation. **No behaviour change unless Core writes the new marker** (Core switch
`SSO_SID_REVOCATION=on`, default off): the extra key is simply absent.

- `AuthContext.session_id`: the v2 `sid` claim (None for v1/service tokens; a malformed value reads as None and never
  fails verification).
- `check_session_revocation` / `session_revocation_check`: a token that carries a `sid` also reads
  `session_revoked_sid:{sid}` (ISO timestamp, written by Core when ONE session -- a refresh family -- is logged out;
  SSO child sessions share their source's sid) in the SAME `MGET` as the per-user keys: one round trip, one timeout.
  `iat <= marker` = revoked (401 in enforce, `would_reject` in warn). It is checked before the jti exemption (an
  exemption only spares force_login's new token from the per-USER marker, and that token has a different sid). A
  malformed sid marker and an unavailable store follow the existing fail modes exactly; a revoked answer is remembered
  like any other. A token without a `sid` reads exactly the keys it read before.

## 0.6.1 (unreleased: no tag yet, the owner tags it)

G6 preparation: local evaluation is usable by every service and never slows a request. **local_mode="off" (the
default) is unchanged**: no catalogue fetch, no Redis read, no new setting read, no new log line.

- **Catalogue fetch has its own timeout**: `configure_permissions(catalogue_timeout_seconds=...)`, env
  `PERMISSION_CATALOGUE_TIMEOUT_SECONDS`, default 10 s, must be > 0, clamped to 30 s (with a
  `permission_catalogue_timeout_clamped` warning). Independent of `timeout_seconds` (the per-check timeout). Before,
  the fetch reused the check timeout, so a 5.4 s catalogue answer on a busy dev host failed every time
  (`permission_catalogue_fetch_failed`, fallback, 10 s back-off, repeat).
- **Background preload, never awaited**: the first staff v2 token a process sees (or the first naming a newer `cv`)
  starts ONE background catalogue fetch (single-flight; a failure is logged and backs off 10 s exactly as before).
  No request waits for it -- in local mode it asks Core, in shadow mode it is counted
  `fallback:catalogue_loading` -- until the catalogue has landed. The preload starts before the freshness check, so
  a stale / unset `authz_ver` no longer keeps the catalogue from loading. (There is no preload at configure time:
  Core's catalogue endpoint needs an authenticated caller and the library has no token of its own until the first
  request.) In 0.6.0 a shadow-mode request awaited the fetch after Core had answered; it no longer does.
  New fallback reason `catalogue_loading`; `catalogue_unavailable` now means "no catalogue, last fetch failed".
- **Reasons in the message text**: `permission_local_shadow`, `permission_local_fallback`,
  `permission_catalogue_fetch_failed`, `permission_catalogue_loaded`, `permission_local_authz_ver_unavailable` and
  `permission_local_mode` now carry their fields in the message as well as in `extra`, e.g.
  `permission_local_shadow outcome=fallback reason=catalogue_loading code=opd.visit.read route=/opd/visits/{visit_id}`
  (formatters that drop `extra` showed only the event name).
- **Services that wrap `_Checker.granted`** (IPD/OPD `app/core/permission_resilience.py`): the 0.6.0 note saying
  they "keep asking Core" was wrong. The local decision is taken in `permissions._decide()`, above `granted`, so those
  services get local evaluation in shadow and local mode; their wrapper applies to the Core path only. Now covered by
  `tests/test_local_with_resilience_wrapper.py`, which runs OPD's `install()` verbatim in off / shadow / local mode.

## 0.6.0 (unreleased: no tag yet, the owner tags it)

Authorization modernisation G5: access token v2 is verified, and permissions can be evaluated LOCALLY from the token,
starting in shadow mode. **With default settings nothing changes** (every BluMax service builds blumax-auth from the dev
tip): the same Core calls, the same cache, the same decisions, the same log lines. Everything below is opt-in.

- **Dual-profile verify.** v1 tokens verify exactly as before. v2 tokens (`ver: 2`, header `typ: at+jwt`) verify the
  same way: `aud` is a list that always contains "blumax", which python-jose accepts against the configured audience;
  `nbf` is enforced (with the existing 30 s leeway). New optional `configure(..., service_audience="blumax-opd")`
  (default None = no check): OBSERVE ONLY in 0.6.0 -- a v2 token whose aud list lacks it is still accepted, counted
  (`blumax_token_service_audience_missing_total`) and logged (`token_service_audience_missing`, at most once a minute).
  Refusing it is G6. `typ` is not checked yet (G6).
- **Local evaluator** (`blumax_auth/local_permissions.py`): the token's `perm = {cv, b}` bitset decoded against Core's
  catalogue (`GET /api/v1/authz/catalogue`, fetched lazily with the caller's own token, cached per version, refetched
  when a token names a newer cv, single-flight, 10 s back-off after a failure). Bitset format mirrors Core's
  `permission_index.pack_indexes` byte for byte (tested against a verbatim copy of Core's encoder).
- **Freshness**: Core's global `authctx:authz_ver` is read from Redis (≤ 5 s per-process cache, default 2 s) and must
  EQUAL the token's `authz_ver` (`!=`, not `<`: a flushed Redis restarts at 0). Missing claim, Redis unavailable, key
  absent, or a different value -> the local answer is not used.
- **Modes**: `configure_permissions(..., local_mode="off"|"shadow"|"local")`, or env `PERMISSION_LOCAL_MODE` when the
  argument is omitted; default **off** (the evaluator is not even built). shadow = Core still decides, the token's
  answer is compared, counted `blumax_permission_local_total{outcome="match"|"mismatch"|"fallback:<reason>"}` and
  logged `permission_local_shadow` on mismatch (WARNING) or fallback (INFO; v1/service tokens counted only),
  rate-limited per (outcome, reason, permission) to one line a minute. local = the token decides when usable
  (`local_allow`/`local_deny`), any fallback asks Core exactly as before, and routes marked `admin=True` always ask
  Core; never a grant or a denial on doubt;
  warn/enforce unchanged (a warn line for a local decision carries `source="local"`).
- Fallback reasons: `v1_token`, `service_token`, `admin_route` (local mode), `token_unreadable`, `no_perm`, `no_authz_ver`,
  `authz_ver_not_configured`, `authz_ver_unavailable`, `authz_ver_unset`, `authz_ver_stale`, `catalogue_unavailable`,
  `catalogue_behind`, `invalid_bitset`, `unknown_code`, `error`.
- New configure_permissions arguments: `local_mode`, `authz_ver_redis_url` (env `PERMISSION_AUTHZ_VER_REDIS_URL`;
  default: reuse the client `configure_session_revocation()` built), `authz_ver_cache_seconds` (env
  `PERMISSION_AUTHZ_VER_CACHE_SECONDS`, clamped to 5), `shadow_log_interval_seconds` (60), `authz_ver_redis` (test seam).
- Platform admins pass first in every mode (unchanged); service tokens always use the Core path until service tokens v2
  (G8). (Corrected in 0.6.1: services that wrap `_Checker.granted` themselves DO get local evaluation.)
- New counters: `blumax_permission_local_total{outcome}`, `blumax_token_service_audience_missing_total`;
  `metrics.local_snapshot()`, `metrics.audience_snapshot()`.

Also in 0.6.0 (merged to dev after 0.5.2, before G5):

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
