"""Per-user session revocation — an opt-in dependency, checked against Redis.

    import blumax_auth
    from blumax_auth.session_revocation import check_session_revocation

    blumax_auth.configure_session_revocation(settings.REDIS_URL)   # once, at startup

    @router.get("/worklist")
    async def worklist(
        ctx: blumax_auth.TenantAuth,
        _: None = Depends(check_session_revocation),
    ):
        ...

Why this exists
----------------
Core (blumax-backend/app/core/session_revocation.py) writes a Redis key
`session_revoked_at:{user_id}` — an ISO timestamp — whenever force_login or
logout deliberately ends a user's OTHER sessions. Core's own
get_current_user/get_current_user_or_service already reject a token whose own
`iat` predates that marker. Every other service verifies the same RS256
tokens through this package but never talks to Core about them again per
request (see jwks.py's docstring) — so without this module, a session Core
considers revoked keeps authenticating everywhere else until the token's own
expiry (up to ~24h — human access tokens run on the daily 02:00 IST reset,
not a short rolling TTL).

This module closes that gap with a SHARED REDIS LOOKUP, not an HTTP call back
to Core: one Redis GET, keyed by the SAME `session_revoked_at:{user_id}`
string Core writes, so both sides agree on the wire format without needing to
agree on anything else. This is deliberately not modeled as an HTTP call
through require_permission's Checker — an explicit decision (see the module
that added this) to avoid adding a per-request network dependency on Core's
availability to every service, merely to ask a question the already-shared
Redis instance can answer directly.

Additive. Nothing in the rest of this package changes: require_auth,
require_tenant, require_role, require_archetype, require_permission and
AuthContext's existing fields are untouched (AuthContext gains one new field,
`issued_at`, defaulted so every existing construction keeps working), and no
existing route is affected until a service opts in by (1) calling
configure_session_revocation() at startup and (2) adding the
check_session_revocation dependency to a route.

The comparison logic: exact jti-exemption, not a timing grace window
----------------------------------------------------------------------
Mirrors blumax-backend's own is_session_revoked (app/core/session_revocation.py)
so the two sides can never disagree on an edge case.

An earlier version of this module (and of Core's own) compared `issued_at` to
the revocation marker with a small grace-window fudge factor, to work around
a JWT `iat` being whole-seconds precision (NumericDate truncation, RFC 7519
§2): AuthService.login's force_login branch revokes every existing session
and then, in the same call, mints the caller's OWN brand-new access token —
close enough in time that the marker and the new token's `iat` could round to
the same second.

That grace window was wrong, not just imprecise: it is symmetric, so any
session — not only the brand-new one that call was about to mint — whose
`iat` happened to fall within a couple of seconds of the revocation write was
also spared. Login (session A) followed by a force_login (session B) seconds
later is the ORDINARY case, not a rare race, so the grace window routinely
protected the very session force_login exists to end.

The actual ambiguous case is narrow and exactly identifiable: the one new
token that same force_login call is about to mint. Core doesn't infer that
from timestamps at all — it knows that token's `jti` the instant
create_access_token returns it, and writes an explicit exemption marker,
`session_revoked_at:{user_id}:exempt:{jti}`, right after minting it. This
module's job is only ever the READ side of that: this is a consuming
service, never the one calling force_login or writing either marker. So
is_session_revoked here checks the exemption key first (if present, the
token is never revoked — no timing involved), and otherwise falls back to a
plain, STRICT `issued_at` comparison with no slack: `issued_at <= revoked_at`
means revoked, full stop. Every session other than an explicitly exempted one
is revoked, regardless of how close in time it was issued.

Redis-failure policy: fail_mode ("open" default | "closed")
-------------------------------------------------------------
This check is layered on top of signature/expiry verification, so by default
a Redis problem (unreachable, or a malformed marker) is read as "nothing to
revoke" and the request passes: losing the shared Redis must not turn into an
outage of every service that opted in. That is `fail_mode="open"`, controlled
degradation: it is never silent. EVERY such outcome logs a WARNING with the
message `redis_unavailable` (reason=redis_unavailable | marker_malformed, plus
user_id and mode) in warn AND enforce mode, so it can be alerted on.

`fail_mode="closed"` (configure_session_revocation(..., fail_mode="closed"),
or env SESSION_REVOCATION_FAIL_MODE when the argument is not given): in
enforce mode a redis_unavailable / marker_malformed outcome is rejected with
the SAME 401 (InvalidToken) a revoked session gets - deliberately not a 503,
so clients keep a single "re-authenticate" path. Choose closed for services
whose endpoints move money or change clinical records irreversibly, where
honouring a session Core already revoked matters more than availability.
The tradeoff: while the shared Redis is down EVERY authenticated request to a
closed service is refused, so closed turns a Redis outage into an outage of
that service. fail_mode is service-wide (like mode); warn mode never rejects,
whatever fail_mode says.

Redis-failure policy, split by risk: fail_mode="split" (opt-in; the default stays "open")
------------------------------------------------------------------------------------------
`fail_mode="split"` (configure_session_revocation(..., fail_mode="split") or env SESSION_REVOCATION_FAIL_MODE=split)
decides per request, in enforce mode, what an unavailable revocation store means:

* writes (anything but GET/HEAD/OPTIONS), routes marked sensitive and a caller with no request to inspect: FAIL
  CLOSED, `SessionRevocationUnavailable` (503, `Retry-After`). A route is sensitive when it depends on
  `session_revocation_check(sensitive=True)` (order-independent: use this one for exports and credential changes),
  or when `require_permission(code, admin=True)` ran earlier in the same request.
* safe reads (GET/HEAD/OPTIONS): keep using the last known session status for at most `stale_read_seconds`
  (env SESSION_REVOCATION_STALE_READ_SECONDS, default 300) counted from this process's last SUCCESSFUL store check;
  a session this process already saw revoked stays revoked (401). After the window: 503 as for a write.
  "Store unavailable" is never read as "valid" beyond that bound, and never at all for writes/sensitive routes.
* a malformed marker is not an availability problem: refused with the same 401 as "closed".

The 10 s breaker keeps its job (one probe per window instead of one timeout per request), but in split mode the
policy above applies during the window too, so a failing store cannot silently let writes through. In "open" mode
the breaker still lets everything pass, as before.

Every unavailable outcome is counted (blumax_auth.metrics.session_snapshot(): store_unavailable, stale_read_served,
rejected_unavailable) and a rate-limited WARNING `revocation_store_unavailable` carries outcome, fail_mode, method,
sensitive and stale_age_seconds.

Optional per-process status cache: SESSION_STATUS_CACHE_SECONDS (default 0 = off, exact old behaviour)
-------------------------------------------------------------------------------------------------
With a value > 0 (2-5 recommended) a definitive answer (not revoked / revoked) is remembered per
(user_id, iat, jti) so ordinary requests do not read the store each time. Bounded LRU
(SESSION_STATUS_CACHE_MAX_ENTRIES, default 10000), single-flight (concurrent requests for the same key share ONE
store read), expiry jittered 0-20 % shorter so entries do not all lapse together. A "not revoked" answer is trusted
for at most the TTL, so a revocation is visible within the TTL. A "revoked" answer is remembered for the marker's
whole life (26 h). An unavailable/malformed answer is NEVER cached; it follows the fail_mode policy. Sensitive
routes bypass the cache (fresh read). Counters: cache_hit, cache_miss, store_reads.

Rollout mode
------------
`mode="warn"` (the default, service-wide, set at configure_session_revocation
time) runs the same check but rejects nothing, and records every decision as
one `session_revocation_check` log event so a service can watch what
enforcement WOULD do before turning it on:

    decision  allow          not revoked (no marker, exempted jti,           INFO
                              or the check could not be meaningfully applied
                              — e.g. no issued_at on the token)
              would_reject   revoked: iat at or before the marker, and       WARNING
                              not exempted
              check_failed   the check itself could not complete             WARNING
                             (see `reason`: redis_unavailable | marker_malformed)

Fields (all plain scalars; never a token): decision, reason (only when not a
plain allow: not_configured | redis_unavailable | marker_malformed |
no_issued_at), mode, user_id, and revoked_at (only when a marker was read and
found revoked).

`mode="enforce"` raises the same kind of 401 require_auth already raises on
an invalid token (blumax_auth.errors.InvalidToken) when the session is
revoked. Enforce mode logs nothing; a rejection is the 401 the caller
receives — matching require_permission's own convention that the mode only
governs the check's own decision, never authentication itself.

Authentication failures raised upstream (bad token, wrong tenant) are
unaffected by this check either way — it only ever runs after require_auth
has already produced a verified AuthContext, via its own Depends(require_auth).

The events are emitted through the stdlib logger
`blumax_auth.session_revocation` with the fields as `extra`. A service that
renders logs through structlog must include `structlog.stdlib.ExtraAdder()`
in its ProcessorFormatter's foreign_pre_chain, or the fields are silently
dropped — the same note as permissions.py's own docstring.
"""
from __future__ import annotations

import asyncio
import contextlib
import logging
import math
import os
import random
import time
from collections import OrderedDict
from collections.abc import Callable
from datetime import datetime
from typing import TYPE_CHECKING, Annotated, Literal

from fastapi import Depends, Request

from blumax_auth import metrics as _metrics
from blumax_auth.context import AuthContext
from blumax_auth.errors import InvalidToken, SessionRevocationUnavailable
from blumax_auth.fastapi import require_auth

if TYPE_CHECKING:
    from redis.asyncio import Redis

_log = logging.getLogger("blumax_auth.session_revocation")

Mode = Literal["enforce", "warn"]
FailMode = Literal["open", "closed", "split"]
FAIL_MODES = ("open", "closed", "split")
FAIL_MODE_ENV = "SESSION_REVOCATION_FAIL_MODE"

#: split mode: how long (seconds, from this process's last SUCCESSFUL store check) a safe read may rely on the last
#: known session status while the store is unavailable. Clamped to [0, MAX_STALE_READ_SECONDS]; 0 = never.
STALE_READ_ENV = "SESSION_REVOCATION_STALE_READ_SECONDS"
DEFAULT_STALE_READ_SECONDS = 300.0
MAX_STALE_READ_SECONDS = 3600.0
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
#: request.state attribute a route (or require_permission(admin=True)) sets to mark itself sensitive.
SENSITIVE_STATE_ATTR = "blumax_sensitive_route"

#: Optional per-process session-status cache (0 = off).
CACHE_SECONDS_ENV = "SESSION_STATUS_CACHE_SECONDS"
CACHE_MAX_ENTRIES_ENV = "SESSION_STATUS_CACHE_MAX_ENTRIES"
DEFAULT_CACHE_MAX_ENTRIES = 10000
CACHE_JITTER = 0.2  # an entry lives between 80 % and 100 % of the TTL
#: A revoked answer cannot become "not revoked" again (the marker only moves forward), so it is kept as long as the
#: marker itself lives (Core: 26 h), well past any token's own expiry.
REVOKED_CACHE_SECONDS = 26 * 3600.0

# A Redis that accepts the connection and never answers (half-open after a Redis restart / failover /
# network blip) makes an un-timed `await redis.get()` wait forever, hanging EVERY authenticated request
# of the service until it is restarted. Every Redis call here is therefore bounded; a timeout is treated
# exactly like "Redis unavailable" (fail_mode decides), never as a wait.
TIMEOUT_ENV = "SESSION_REVOCATION_REDIS_TIMEOUT_SECONDS"
DEFAULT_REDIS_TIMEOUT_SECONDS = 2.0


# After a Redis failure the next requests skip Redis for this long and apply fail_mode at once. A Redis that hangs
# (failover, half-open connection) used to cost every authenticated request two full timeouts (~4 s at the default),
# for as long as it hung; now one request per window pays one timeout. 0 turns the breaker off.
BREAKER_ENV = "SESSION_REVOCATION_BREAKER_SECONDS"
DEFAULT_BREAKER_SECONDS = 10.0
#: The reason given while the breaker is open: treated exactly like "redis_unavailable" (fail_mode decides), but the
#: alerting `redis_unavailable` warning was already logged by the failure that opened the window.
REASON_SKIPPED = "redis_unavailable_skipped"


def _clock() -> float:
    """The breaker's clock (its own name, so a test can move it without stopping the event loop's timers)."""
    return time.monotonic()


def _breaker_seconds() -> float:
    try:
        value = float(os.environ.get(BREAKER_ENV, "") or DEFAULT_BREAKER_SECONDS)
    except ValueError:
        return DEFAULT_BREAKER_SECONDS
    return max(value, 0.0)


def _redis_timeout() -> float:
    try:
        value = float(os.environ.get(TIMEOUT_ENV, "") or DEFAULT_REDIS_TIMEOUT_SECONDS)
    except ValueError:
        return DEFAULT_REDIS_TIMEOUT_SECONDS
    return value if value > 0 else DEFAULT_REDIS_TIMEOUT_SECONDS


def _float_env(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, "").strip() or default)
    except ValueError:
        return default


def _stale_read_seconds_from_env() -> float:
    return min(max(_float_env(STALE_READ_ENV, DEFAULT_STALE_READ_SECONDS), 0.0), MAX_STALE_READ_SECONDS)


def _cache_seconds_from_env() -> float:
    return max(_float_env(CACHE_SECONDS_ENV, 0.0), 0.0)


def _cache_max_from_env() -> int:
    return max(int(_float_env(CACHE_MAX_ENTRIES_ENV, DEFAULT_CACHE_MAX_ENTRIES)), 1)


def _key(user_id: object) -> str:
    # Same format Core writes: f"session_revoked_at:{user_id}". user_id is
    # whatever AuthContext carries (a uuid.UUID); str() renders it the same
    # way Core's own str(user_id) does.
    return f"session_revoked_at:{user_id}"


def _exempt_key(user_id: object, jti: str) -> str:
    # Same format Core writes: f"session_revoked_at:{user_id}:exempt:{jti}"
    # (app/core/session_revocation.py::_exempt_key), written once by
    # AuthService.login's force_login branch right after minting its own new
    # access token, so that token's own jti is spared from the revocation it
    # just triggered.
    return f"session_revoked_at:{user_id}:exempt:{jti}"


class _Checker:
    """One configured Redis connection plus the mode it defaults to."""

    def __init__(
        self,
        redis: Redis,
        *,
        mode: Mode,
        fail_mode: FailMode = "open",
        stale_read_seconds: float = DEFAULT_STALE_READ_SECONDS,
        cache_seconds: float = 0.0,
        cache_max_entries: int = DEFAULT_CACHE_MAX_ENTRIES,
    ) -> None:
        self.redis = redis
        self.mode = mode
        self.fail_mode = fail_mode
        self.stale_read_seconds = min(max(stale_read_seconds, 0.0), MAX_STALE_READ_SECONDS)
        #: monotonic time until which Redis is not asked (the breaker; see BREAKER_ENV).
        self._skip_until = 0.0
        #: monotonic time of this process's last SUCCESSFUL store answer (None = none yet); anchors split's stale window.
        self.last_ok: float | None = None
        # Session-status cache (off when cache_seconds <= 0). `_revoked` is kept in every configuration (bounded,
        # revoked answers only) so split mode never forgets a session it saw revoked; it only ANSWERS requests
        # when the cache is on, or in split's unavailable path.
        self.cache_seconds = max(cache_seconds, 0.0)
        self.cache_max_entries = max(cache_max_entries, 1)
        self._valid: OrderedDict[tuple, float] = OrderedDict()
        self._revoked: OrderedDict[tuple, tuple[float, datetime | None]] = OrderedDict()
        self._inflight: dict[tuple, asyncio.Task] = {}

    # ── cache layer ──────────────────────────────────────────────────────────

    @staticmethod
    def _cache_key(user_id: object, issued_at: datetime, jti: str | None) -> tuple:
        return (str(user_id), int(issued_at.timestamp()), jti)

    def _remember(self, key: tuple, revoked: bool, revoked_at: datetime | None) -> None:
        now = _clock()
        if revoked:
            self._revoked[key] = (now + REVOKED_CACHE_SECONDS, revoked_at)
            self._revoked.move_to_end(key)
            while len(self._revoked) > self.cache_max_entries:
                self._revoked.popitem(last=False)
        elif self.cache_seconds > 0:
            self._valid[key] = now + self.cache_seconds * (1.0 - CACHE_JITTER * random.random())
            self._valid.move_to_end(key)
            while len(self._valid) > self.cache_max_entries:
                self._valid.popitem(last=False)

    def known_revoked(self, user_id: object, issued_at: datetime | None, jti: str | None) -> tuple[bool, datetime | None]:
        """Has this process already seen this exact session revoked (and not yet forgotten it)?"""
        if issued_at is None:
            return False, None
        key = self._cache_key(user_id, issued_at, jti)
        entry = self._revoked.get(key)
        if entry is None or entry[0] <= _clock():
            return False, None
        self._revoked.move_to_end(key)
        return True, entry[1]

    async def lookup(
        self, user_id: object, issued_at: datetime | None, jti: str | None, *, fresh: bool = False
    ) -> tuple[bool, str | None, datetime | None]:
        """is_revoked() through the optional cache. Same return shape.

        Cache off: exactly is_revoked(). Cache on: a definitive answer is served from memory for its TTL; a miss
        triggers one store read shared by every concurrent caller of the same key (single-flight). `fresh=True`
        (sensitive routes) skips the lookup and the join, but still stores the answer it got. An unavailable or
        malformed answer (reason set) is returned to the caller for the fail_mode policy and never stored.
        """
        if self.cache_seconds <= 0 or issued_at is None:
            return await self.is_revoked(user_id, issued_at, jti)
        key = self._cache_key(user_id, issued_at, jti)
        if not fresh:
            now = _clock()
            hit, revoked_at = self.known_revoked(user_id, issued_at, jti)
            if hit:
                _metrics.session_revocation_event("cache_hit")
                return True, None, revoked_at
            expires = self._valid.get(key)
            if expires is not None and expires > now:
                self._valid.move_to_end(key)
                _metrics.session_revocation_event("cache_hit")
                return False, None, None
            _metrics.session_revocation_event("cache_miss")
            task = self._inflight.get(key)
            if task is None:
                task = asyncio.ensure_future(self._read_and_remember(key, user_id, issued_at, jti))
                self._inflight[key] = task
                task.add_done_callback(lambda _t, k=key: self._inflight.pop(k, None))
            # shield: one waiter being cancelled (client disconnect) must not cancel the read the others share
            return await asyncio.shield(task)
        _metrics.session_revocation_event("cache_miss")
        return await self._read_and_remember(key, user_id, issued_at, jti)

    async def _read_and_remember(
        self, key: tuple, user_id: object, issued_at: datetime, jti: str | None
    ) -> tuple[bool, str | None, datetime | None]:
        result = await self.is_revoked(user_id, issued_at, jti)
        revoked, reason, revoked_at = result
        if reason is None:
            self._remember(key, revoked, revoked_at)
        return result

    async def is_revoked(
        self, user_id: object, issued_at: datetime | None, jti: str | None
    ) -> tuple[bool, str | None, datetime | None]:
        """Returns (revoked, reason_if_ambiguous, revoked_at_if_known).

        Mirrors blumax-backend's is_session_revoked: checks the exemption key
        first (if `jti` was explicitly exempted, never revoked — no timing
        involved), then falls back to a strict, no-grace `issued_at`
        comparison. False (never revoked) on every kind of ambiguity — no
        issued_at to compare, no marker set, Redis unreachable, or a
        malformed marker. This is a READ-only mirror: this service never
        writes either the revocation marker or an exemption — only Core does
        (via force_login/logout).
        """
        if issued_at is None:
            return False, "no_issued_at", None
        if _clock() < self._skip_until:
            return False, REASON_SKIPPED, None

        # The exemption key and the marker in ONE round trip (MGET), bounded by one timeout. A client without mget
        # (a test double) is asked key by key; the first failure ends the check either way, so a hung Redis costs
        # one timeout per request, never two.
        keys = [_exempt_key(user_id, jti), _key(user_id)] if jti is not None else [_key(user_id)]
        _metrics.session_revocation_event("store_reads")
        try:
            mget = getattr(self.redis, "mget", None)
            if mget is not None:
                values = await asyncio.wait_for(mget(keys), _redis_timeout())
            else:
                values = [await asyncio.wait_for(self.redis.get(k), _redis_timeout()) for k in keys]
        except Exception:
            self._skip_until = _clock() + _breaker_seconds()
            _log.warning("session_revocation_check_unavailable", extra={"user_id": str(user_id)})
            return False, "redis_unavailable", None
        self.last_ok = _clock()
        if jti is not None and values[0]:
            return False, None, None
        raw = values[-1]
        if not raw:
            return False, None, None
        try:
            revoked_at = datetime.fromisoformat(raw)
        except ValueError:
            _log.warning("session_revocation_marker_malformed", extra={"user_id": str(user_id)})
            return False, "marker_malformed", None
        revoked = issued_at <= revoked_at
        if revoked:  # remembered in every configuration: split mode must not forget a session it saw revoked
            self._remember(self._cache_key(user_id, issued_at, jti), True, revoked_at)
        return revoked, None, revoked_at


_checker: _Checker | None = None


def configure_session_revocation(
    redis_url: str,
    *,
    mode: Mode = "warn",
    fail_mode: FailMode | None = None,
    stale_read_seconds: float | None = None,
    status_cache_seconds: float | None = None,
    status_cache_max_entries: int | None = None,
) -> None:
    """Point this service at the shared Redis for session-revocation checks.

    Call once, at service startup — the same shape as configure_permissions().
    Connects via redis.asyncio (an optional dependency of this package,
    imported here rather than at module load time, so services that never
    call this function need not install it), the same client blumax-backend
    itself uses for this purpose (app/core/redis.py), so both sides read/
    write the identical key format over the identical protocol.

    redis_url  A redis:// / rediss:// connection URL for the SAME Redis
               instance Core writes session_revoked_at:{user_id} (and its
               exemption keys) to. Sharing that instance (not merely the key
               format) is what makes this a same-process GET rather than a
               network call to Core.
    mode       "warn" (default) or "enforce" — see the module docstring's
               "Rollout mode" section. check_session_revocation() honors
               whichever was set here.
    fail_mode  "open" (default), "closed" or "split" - what enforce mode does when
               Redis is unavailable; see "Redis-failure policy" in the module
               docstring. When None, read from env SESSION_REVOCATION_FAIL_MODE
               (unset/empty -> "open"). An invalid value raises ValueError.
    stale_read_seconds
               split only: the bound for serving safe reads from the last known
               status. None -> env SESSION_REVOCATION_STALE_READ_SECONDS (default 300).
    status_cache_seconds / status_cache_max_entries
               the optional per-process status cache. None -> env
               SESSION_STATUS_CACHE_SECONDS (default 0 = off) and
               SESSION_STATUS_CACHE_MAX_ENTRIES (default 10000).
    """
    global _checker
    if not redis_url or not redis_url.strip():
        raise ValueError("redis_url is required")
    if mode not in ("enforce", "warn"):
        raise ValueError(f"mode must be 'enforce' or 'warn', got {mode!r}")

    if fail_mode is None:
        fail_mode = os.environ.get(FAIL_MODE_ENV, "").strip().lower() or "open"  # type: ignore[assignment]
    if fail_mode not in FAIL_MODES:
        raise ValueError(f"fail_mode must be 'open', 'closed' or 'split', got {fail_mode!r}")

    import redis.asyncio as aioredis  # noqa: PLC0415 — optional dep, only needed if this is used

    _checker = _Checker(
        aioredis.Redis.from_url(
            redis_url, decode_responses=True,
            socket_connect_timeout=_redis_timeout(), socket_timeout=_redis_timeout(),
            health_check_interval=30,
        ),
        mode=mode, fail_mode=fail_mode,
        stale_read_seconds=_stale_read_seconds_from_env() if stale_read_seconds is None else stale_read_seconds,
        cache_seconds=_cache_seconds_from_env() if status_cache_seconds is None else status_cache_seconds,
        cache_max_entries=_cache_max_from_env() if status_cache_max_entries is None else status_cache_max_entries,
    )


async def aclose_session_revocation() -> None:
    """Close the Redis connection. Call from the app's shutdown hook."""
    if _checker is not None:
        with contextlib.suppress(Exception):
            await _checker.redis.aclose()


def reset_session_revocation() -> None:
    """Drop the session-revocation configuration. Tests only."""
    global _checker
    _checker = None
    _last_logged.clear()


async def check_session_revocation(
    ctx: Annotated[AuthContext, Depends(require_auth)],
    request: Request = None,  # type: ignore[assignment]  # FastAPI injects it; None only for a direct call
) -> None:
    """FastAPI dependency: reject (or, in warn mode, merely log) a caller
    whose session Core has revoked.

    Add this alongside require_auth/require_tenant/require_permission on any
    route that should honor Core's force_login/logout revocation. It is
    itself additive — a route that doesn't depend on it is entirely
    unaffected — and it never widens what require_auth already verified; it
    can only narrow (enforce mode) or observe (warn mode) it further.

    The mode is whatever configure_session_revocation() was given; there is
    no per-route override, matching the request that this be a simple opt-in
    switch a service flips once, service-wide, exactly like
    configure_permissions()'s own mode staging is meant to be watched in warn
    before a service turns enforcement on.

    enforce: raises InvalidToken (401) if the caller's token is revoked —
             its jti is not exempted, and its issued_at is at or before a
             revocation marker for its user. With fail_mode="split" and the
             store unavailable: SessionRevocationUnavailable (503) for a write
             or a sensitive route, and for a read once the stale window has
             passed (see the module docstring).
    warn:    performs the same check, logs a session_revocation_check event,
             and never rejects.

    Unconfigured: warn mode logs check_failed/not_configured and passes. If
    no mode has ever been configured there is no way to tell what the caller
    intended, so this treats "unconfigured" as warn's own behavior — passing
    but logging — rather than guessing enforce; a service that truly wants
    enforcement calls configure_session_revocation(mode="enforce") and this
    path is never reached.

    This plain dependency treats a route as sensitive only when
    require_permission(..., admin=True) already ran in the request; use
    session_revocation_check(sensitive=True) to mark one explicitly.
    """
    await _check(ctx, request, sensitive=False)


def session_revocation_check(*, sensitive: bool = False) -> Callable[..., object]:
    """check_session_revocation with an explicit sensitivity mark.

        Depends(session_revocation_check(sensitive=True))   # exports, credential changes, admin routes

    sensitive=True: under fail_mode="split" the route fails closed (503) whatever the HTTP method when the store is
    unavailable, and the status cache is bypassed (fresh store read). sensitive=False behaves exactly like
    check_session_revocation. Other fail modes are unaffected by the mark.
    """

    async def _dep(
        ctx: Annotated[AuthContext, Depends(require_auth)],
        request: Request,
    ) -> None:
        await _check(ctx, request, sensitive=sensitive)

    return _dep


_last_logged: dict[str, float] = {}
_LOG_EVERY_SECONDS = 5.0


def _log_unavailable(outcome: str, checker: _Checker, ctx: AuthContext, method: str | None, sensitive: bool,
                     stale_age: float | None, reason: str | None) -> None:
    """`revocation_store_unavailable`, at most once per outcome per 5 s per process (the counters carry the volume)."""
    now = _clock()
    if now - _last_logged.get(outcome, -1e9) < _LOG_EVERY_SECONDS:
        return
    _last_logged[outcome] = now
    _log.warning(
        "revocation_store_unavailable",
        extra={
            "outcome": outcome, "reason": reason, "fail_mode": checker.fail_mode, "method": method,
            "sensitive": sensitive,
            "stale_age_seconds": None if stale_age is None else round(stale_age, 1),
            "user_id": str(ctx.user_id),
        },
    )


def _unavailable_error() -> SessionRevocationUnavailable:
    exc = SessionRevocationUnavailable()
    exc.headers = {"Retry-After": str(max(1, math.ceil(_breaker_seconds())))}
    return exc


async def _check(ctx: AuthContext, request: Request | None, *, sensitive: bool) -> None:
    checker = _checker
    if checker is None:
        _emit(ctx, decision="check_failed", reason="not_configured")
        return

    method = request.method.upper() if request is not None else None
    sensitive = sensitive or bool(request is not None and getattr(request.state, SENSITIVE_STATE_ATTR, False))
    revoked, reason, revoked_at = await checker.lookup(ctx.user_id, ctx.issued_at, ctx.jti, fresh=sensitive)

    if reason is not None:
        failed = reason in ("redis_unavailable", REASON_SKIPPED, "marker_malformed")
        unavailable = reason in ("redis_unavailable", REASON_SKIPPED)
        if unavailable:
            _metrics.session_revocation_event("store_unavailable")
        if failed and reason != REASON_SKIPPED:
            # Always visible, in either mode and either fail_mode, so the
            # degradation can be alerted on (see "Redis-failure policy").
            _log.warning(
                "redis_unavailable",
                extra={
                    "reason": reason,
                    "mode": checker.mode,
                    "fail_mode": checker.fail_mode,
                    "user_id": str(ctx.user_id),
                },
            )
        if checker.mode == "warn":
            _emit(ctx, decision="check_failed" if failed else "allow", reason=reason)
        elif failed and checker.fail_mode == "closed":
            raise InvalidToken("Session has been revoked")
        elif failed and checker.fail_mode == "split":
            _split_unavailable(checker, ctx, method, sensitive, reason)
        return

    if revoked:
        if checker.mode == "warn":
            _emit(ctx, decision="would_reject", revoked_at=revoked_at)
            return
        _metrics.session_revocation_event("revoked")
        raise InvalidToken("Session has been revoked")

    if checker.mode == "warn":
        _emit(ctx, decision="allow")
    return


def _split_unavailable(
    checker: _Checker, ctx: AuthContext, method: str | None, sensitive: bool, reason: str
) -> None:
    """The split-by-risk decision for an unavailable store (enforce mode). Raises, or returns to allow."""
    if reason == "marker_malformed":
        # A marker exists for this user and cannot be read; the stale window says nothing about it.
        _metrics.session_revocation_event("rejected_unavailable")
        raise InvalidToken("Session has been revoked")
    safe_read = method in SAFE_METHODS  # unknown method (direct call) is treated as a write
    if safe_read and not sensitive:
        seen_revoked, _ = checker.known_revoked(ctx.user_id, ctx.issued_at, ctx.jti)
        if seen_revoked:
            _metrics.session_revocation_event("revoked")
            raise InvalidToken("Session has been revoked")
        age = None if checker.last_ok is None else _clock() - checker.last_ok
        if age is not None and age <= checker.stale_read_seconds:
            _metrics.session_revocation_event("stale_read_served")
            _log_unavailable("stale_read_served", checker, ctx, method, sensitive, age, reason)
            return
        _metrics.session_revocation_event("rejected_unavailable")
        _log_unavailable("rejected_unavailable", checker, ctx, method, sensitive, age, reason)
        raise _unavailable_error()
    _metrics.session_revocation_event("rejected_unavailable")
    _log_unavailable("rejected_unavailable", checker, ctx, method, sensitive, None, reason)
    raise _unavailable_error()


def _emit(
    ctx: AuthContext,
    *,
    decision: str,
    reason: str | None = None,
    revoked_at: datetime | None = None,
) -> None:
    """One `session_revocation_check` event. Plain scalars only: no token."""
    extra: dict[str, object] = {
        "decision": decision,
        "mode": "warn",
        "user_id": str(ctx.user_id),
    }
    if reason is not None:
        extra["reason"] = reason
    if revoked_at is not None:
        extra["revoked_at"] = revoked_at.isoformat()
    _log.log(
        logging.INFO if decision == "allow" else logging.WARNING,
        "session_revocation_check",
        extra=extra,
    )
