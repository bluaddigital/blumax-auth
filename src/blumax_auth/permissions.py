"""Permission checks against Core — an opt-in dependency.

    from blumax_auth import configure_permissions, require_permission

    configure_permissions(core_url=settings.CORE_API_URL)      # once, at startup

    @router.post("/visits/{id}/start-consultation")
    async def start(ctx: AuthContext = Depends(require_permission("opd.consultation.create"))):
        ...

Why this exists
---------------
The token carries the caller's ROLE and ARCHETYPE, never a list of permissions,
and that does not change here: a permission list in a JWT is large, and a role
edit would not reach a token already issued. Core owns roles and their grants, so
a service that wants to enforce a specific code asks Core — with the caller's own
token — what that caller holds (GET /api/v1/me/permissions), and caches the answer
briefly.

Additive. Nothing in the rest of this package changes: require_auth,
require_tenant, require_role, require_archetype and the AuthContext are untouched,
and no existing route uses anything here until a service opts in by putting
require_permission() on it. No permission data is ever added to a token or to
AuthContext.

The rules the design is built on
--------------------------------
* Authentication first, unchanged. The token is verified locally (signature,
  issuer, audience, expiry) by the same require_tenant() every tenant route
  already uses. An invalid or expired token is refused before Core is asked
  anything.
* The tenant is the SIGNED tenant. Core is called with the `tid` claim, never
  with a header the caller typed; a request whose X-Tenant-ID disagrees with the
  token is refused by require_tenant(), exactly as everywhere else.
* One route, one code. require_permission() takes a single code, so a route has
  one deterministic answer — there is no "A or B".
* Fail closed. If Core cannot be reached, times out, answers 5xx, or answers with
  something that is not the documented shape, the request is refused (503). An
  unavailable Core is never read as "allowed", and a failure is never cached.
* The cache is per CALLER, not per permission. It stores what Core said one
  token holds in one tenant, keyed by (tenant_id, user_id, sha256(token)). Two
  users in the same tenant, two tokens of the same user, and the same user in two
  tenants all get separate entries, so a result can never be replayed for a
  different caller. Only successful answers are stored, for `ttl_seconds`
  (default 30). After that — or once the entry is evicted — the next request asks
  Core again, so a role edit takes effect within the TTL (Core itself invalidates
  its own role cache on every edit, so the TTL is the whole delay).
* Platform admins pass, as they do in require_role and require_archetype: their
  authority is cross-tenant by definition and Core's PLATFORM_ADMIN role is not a
  list of every code a service enforces.

Rollout mode
------------
`mode="warn"` runs the same check but refuses nothing, and records every decision
as one `permission_check` log event so a service can watch what enforcement WOULD
do before turning it on:

    decision  allow         the caller holds the code                       INFO
              would_deny    Core answered and the caller lacks the code     WARNING
              check_failed  the check could not be completed (see `reason`) WARNING

Fields (all plain scalars; never a token, never a permission list): decision,
reason (only when not allow: missing_permission | core_unavailable |
core_rejected_token | core_forbidden | not_configured | error), mode, permission,
route (the route TEMPLATE, e.g. /opd/visits/{visit_id}/cancel — never a concrete
path), method, tenant_id, user_id, role, archetype, is_service, cached (whether the
answer came from this process's cache), and — only when Core was actually asked —
core_latency_ms and, when Core answered with an error, core_status. A platform admin
(who is never sent to Core) is logged as allow with reason "platform_admin".

Authentication failures raised upstream of the permission check (bad token, wrong
tenant) are not affected by the mode — the mode only governs the permission
decision. Enforce mode logs nothing; a denial is the 403 the caller receives.

The events are emitted through the stdlib logger `blumax_auth.permissions` with the
fields as `extra`. A service that renders logs through structlog must include
`structlog.stdlib.ExtraAdder()` in its ProcessorFormatter's foreign_pre_chain, or
the fields are silently dropped.

Riding out a Core outage (containment layers C1-C4)
---------------------------------------------------
C1  Single-flight + per-caller cache of successful answers (above).
C2  Circuit breaker: after `breaker_failures` consecutive "Core is unwell" outcomes
    (no answer, 5xx, malformed) lookups are refused at once for
    `breaker_open_seconds`, then one probe goes through. Same 503, never a grant.
    Default 5 / 10 s; `breaker_failures=0` turns it off.
C3  One retry on NO answer (`retry_on_no_answer`, default on): when the ask timed
    out or could not connect, it is asked once more after `retry_pause_seconds`
    (0.15 s). Never when Core answered — a 401, 403, 404, 5xx or malformed body is
    the outcome as it stands — and never while the breaker is open. The retry runs
    inside the single-flight fetch, so concurrent waiters share it. It is a read
    (GET /api/v1/me/permissions): it cannot duplicate a write and does not change
    the decision, only whether one is reached. Each failed attempt counts towards
    the breaker. Worst case for one check: 2 x timeout + pause.
C4  Bounded stale-on-error (`stale_grace_seconds`, default 0 = OFF, capped at 120):
    when the lookup still fails with no answer, a 5xx or an open breaker, and this
    process holds Core's last SUCCESSFUL answer for the same tenant + user +
    sha256(token) whose TTL ran out less than the grace ago, that answer is used
    (allow or deny, exactly as Core gave it). Every stale serve is logged
    (`permission_check_served_stale`, WARNING) and counted. Never: for a caller with
    no earlier success in this process; after Core answered 401/403/404 for that key
    (the held answer is dropped); on a malformed answer; on a route marked
    `admin=True` (require_permission / check_permission). Session revocation and
    token expiry are checked upstream in require_tenant() and still apply. While on,
    a grant Core withdrew in the last TTL + grace seconds is still honoured during an
    outage: enabling it is an owner decision per service (OD-DEP-1).

Counters (optional): `blumax_core_permission_calls_total{outcome}` when the process
has BLUMAX_METRICS_ENABLED=true and prometheus_client installed; see metrics.py.

Local evaluation from access token v2 (0.6.0): local_mode = "off" | "shadow" | "local"
-------------------------------------------------------------------------------------
configure_permissions(local_mode=...) or, when the argument is not given, env PERMISSION_LOCAL_MODE. Unset -> "off".

off     (DEFAULT) Exactly the behaviour above: no catalogue fetch, no Redis read, no extra log line or counter, the
        local evaluator is not even built. Every BluMax service builds blumax-auth from the dev tip, so this default
        must stay a no-op.
shadow  The decision still comes from Core, exactly as above (same calls, cache, breaker, stale serving, warn/enforce).
        After Core has answered, the token's own answer is computed too (local_permissions.py) and compared:
        counted as blumax_permission_local_total{outcome="match"|"mismatch"|"fallback:<reason>"}; logged as
        `permission_local_shadow` only on a mismatch (WARNING) or a fallback (INFO; v1_token and service_token are
        counted, never logged), at most once per (outcome, reason, permission) per shadow_log_interval_seconds (60),
        with the number suppressed since the last line. When Core fails, nothing is compared.
local   The decision comes from the token when its answer is usable (counted local_allow / local_deny) -- Core is not
        asked. Otherwise (any fallback reason) it is asked exactly as in "off", and the fallback is counted and logged
        (`permission_local_fallback`, same rate limit). Routes marked admin=True always ask Core (fallback
        admin_route, counted only). Never a grant on doubt: a fallback is never a yes or a no.
        warn/enforce semantics of require_permission are unchanged; a warn-mode `permission_check` line for a local
        decision carries `source="local"` (lines from Core carry no source field, exactly as before).

Platform admins pass before any of this, in every mode (unchanged). Service tokens always use the Core path
(fallback service_token) until service tokens v2 (G8). Fallback reasons and the freshness rule: local_permissions.py.
A service that wraps `_Checker.granted` itself (IPD/OPD permission_resilience.py) keeps calling Core in every mode.
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import time
import uuid
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass
from typing import Annotated, Literal

import httpx
from fastapi import Depends, Request
from fastapi.security import HTTPAuthorizationCredentials

from blumax_auth.context import AuthContext
from blumax_auth.errors import AuthError, Forbidden, InvalidToken, MissingCredentials
from blumax_auth.fastapi import _bearer, require_tenant
from blumax_auth.local_permissions import (
    DEFAULT_AUTHZ_VER_CACHE_SECONDS,
    ENV_REDIS_URL,
    MAX_AUTHZ_VER_CACHE_SECONDS,
    LocalDecision,
    LocalEvaluator,
    env_cache_seconds,
)
from blumax_auth.metrics import core_permission_call as _count
from blumax_auth.metrics import permission_local_event as _count_local

_log = logging.getLogger("blumax_auth.permissions")

#: Core's endpoint for "what does this caller hold?".
PERMISSIONS_PATH = "/api/v1/me/permissions"

#: Hard upper bound for C4's grace (a larger configured value is clamped to it).
MAX_STALE_GRACE_SECONDS = 120.0

Mode = Literal["enforce", "warn"]
LocalMode = Literal["off", "shadow", "local"]
LOCAL_MODES = ("off", "shadow", "local")
ENV_LOCAL_MODE = "PERMISSION_LOCAL_MODE"
#: Fallback reasons that are counted but never logged (expected while tokens v2 / service tokens v2 roll out).
_QUIET_REASONS = frozenset({"v1_token", "service_token", "admin_route"})
_CacheKey = tuple[uuid.UUID, uuid.UUID, str]


@dataclass(frozen=True)
class _Fetched:
    """What one call to Core produced."""

    codes: frozenset[str]
    latency_ms: float


@dataclass(frozen=True)
class _Answer:
    """The codes a caller holds, and how this check got them (for the warn log)."""

    codes: frozenset[str]
    cached: bool
    latency_ms: float | None = None      # only when Core was actually asked
    source: str = "core"                 # "local": decided from the token (local_mode="local")


class PermissionCheckUnavailable(AuthError):
    """Core could not answer, so the permission could not be verified.

    503, not 401/403: the caller did nothing wrong. The request is still refused —
    an unanswerable check is never an implicit yes.
    """

    status_code = 503
    error_code = "PERMISSION_CHECK_UNAVAILABLE"
    message = "Permissions could not be verified right now; the request was refused"


class _Checker:
    """One configured connection to Core plus its per-caller answer cache."""

    def __init__(
        self,
        *,
        core_url: str,
        ttl_seconds: float,
        timeout_seconds: float,
        max_entries: int,
        transport: httpx.AsyncBaseTransport | None,
        clock: Callable[[], float],
        breaker_failures: int = 0,
        breaker_open_seconds: float = 10.0,
        retry_on_no_answer: bool = False,
        retry_pause_seconds: float = 0.15,
        stale_grace_seconds: float = 0.0,
        local: LocalEvaluator | None = None,
        local_mode: LocalMode = "off",
        shadow_log_interval_seconds: float = 60.0,
    ) -> None:
        # 0.6.0: None while local_mode is "off" (the default) -- then nothing below differs from 0.5.x.
        self.local = local
        self.local_mode: LocalMode = local_mode if local is not None else "off"
        self._log_interval = shadow_log_interval_seconds
        self._logged: dict[tuple[str, str, str], tuple[float, int]] = {}
        self._core_url = core_url.rstrip("/")
        self._ttl = ttl_seconds
        self._timeout = timeout_seconds
        self._max = max_entries
        self._transport = transport
        self._clock = clock
        self._client: httpx.AsyncClient | None = None
        # Circuit breaker (APP-007): after `breaker_failures` consecutive "Core is unwell" outcomes (unreachable, timeout, 5xx, malformed) further
        # lookups are refused at once, with the same PermissionCheckUnavailable (503, fail-closed, never a grant), until `breaker_open_seconds`
        # pass; then one probe goes through. 0 disables the breaker. A 401/403/404 means Core ANSWERED: it counts as reachable.
        self._breaker_limit = breaker_failures
        self._breaker_open_seconds = breaker_open_seconds
        self._breaker_failures = 0
        self._breaker_open_until = 0.0
        # C3: one more ask when the first got no answer at all.
        self._retry = retry_on_no_answer
        self._retry_pause = retry_pause_seconds
        # C4: the last successful answer per caller key, kept `grace` past its TTL. Same key and same insertion==expiry order as the cache.
        self._grace = min(max(0.0, stale_grace_seconds), MAX_STALE_GRACE_SECONDS)
        self._last_good: OrderedDict[_CacheKey, tuple[float, frozenset[str]]] = OrderedDict()
        # Insertion order == expiry order (one constant TTL), so expired entries
        # are always at the front and eviction is a cheap popitem.
        self._cache: OrderedDict[_CacheKey, tuple[float, frozenset[str]]] = OrderedDict()
        self._inflight: dict[_CacheKey, asyncio.Task[_Fetched]] = {}

    # ── public ────────────────────────────────────────────────────────────────

    async def granted(self, ctx: AuthContext, token: str, *, allow_stale: bool = True) -> _Answer:
        """The codes Core says this caller holds in the token's tenant.

        allow_stale=False (routes marked admin) never takes C4's stale answer.
        """
        assert ctx.tenant_id is not None  # require_tenant() guarantees it
        key: _CacheKey = (ctx.tenant_id, ctx.user_id, hashlib.sha256(token.encode()).hexdigest())

        hit = self._lookup(key)
        if hit is not None:
            return _Answer(codes=hit, cached=True)

        # Concurrent misses for the same caller share ONE call to Core — and one
        # outcome, including a failure, so an outage costs one timeout, not one per
        # queued request. The fetch runs as its own task so a cancelled request
        # (client hung up) cannot cancel it for everyone else waiting on it.
        task = self._inflight.get(key)
        if task is None:
            task = asyncio.ensure_future(self._fetch(key, ctx.tenant_id, token))
            self._inflight[key] = task
            task.add_done_callback(lambda t, k=key: self._settled(k, t))
        try:
            fetched = await asyncio.shield(task)
        except PermissionCheckUnavailable as exc:
            stale = self._stale(key, exc) if allow_stale else None
            if stale is None:
                raise
            expires_at, codes = stale
            _log.warning(
                "permission_check_served_stale",
                extra={
                    "tenant_id": str(ctx.tenant_id), "user_id": str(ctx.user_id),
                    "seconds_past_expiry": round(max(0.0, self._clock() - expires_at), 1),
                    "core_status": getattr(exc, "core_status", None),
                },
            )
            _count("stale_served")
            return _Answer(codes=codes, cached=True)
        return _Answer(codes=fetched.codes, cached=False, latency_ms=fetched.latency_ms)

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None
        if self.local is not None:
            await self.local.aclose()

    # ── local evaluation (0.6.0; never reached while local_mode is "off") ──────

    def note_local(
        self, event: str, ctx: AuthContext, code: str, decision: LocalDecision, *,
        outcome: str, route: str | None, core_decision: bool | None = None,
    ) -> None:
        """Count one outcome and log it, rate-limited per (outcome, reason, permission)."""
        _count_local(outcome)
        if not (outcome == "mismatch" or outcome.startswith("fallback:")) or decision.reason in _QUIET_REASONS:
            return  # match / local_allow / local_deny are counted only
        key = (outcome, decision.reason or "", code)
        now = self._clock()
        last = self._logged.get(key)
        if last is not None and now - last[0] < self._log_interval:
            self._logged[key] = (last[0], last[1] + 1)
            return
        if len(self._logged) > 5000:
            self._logged.clear()
        self._logged[key] = (now, 0)
        extra: dict[str, object] = {
            "outcome": "mismatch" if outcome == "mismatch" else "fallback",
            "permission": code,
            "route": route or "<unknown>",
            "tenant_id": str(ctx.tenant_id),
            "user_id": str(ctx.user_id),
            "suppressed": last[1] if last is not None else 0,
        }
        if decision.reason is not None:
            extra["reason"] = decision.reason
        if core_decision is not None:
            extra["core_decision"] = "allow" if core_decision else "deny"
        if decision.granted is not None:
            extra["local_decision"] = "allow" if decision.granted else "deny"
        for name in ("catalogue_version", "token_authz_ver", "current_authz_ver"):
            value = getattr(decision, name)
            if value is not None:
                extra[name] = value
        _log.log(logging.WARNING if outcome == "mismatch" else logging.INFO, event, extra=extra)

    def clear(self) -> None:
        self._cache.clear()
        self._last_good.clear()

    # ── cache ─────────────────────────────────────────────────────────────────

    def _lookup(self, key: _CacheKey) -> frozenset[str] | None:
        entry = self._cache.get(key)
        if entry is None:
            return None
        expires_at, codes = entry
        if self._clock() >= expires_at:
            del self._cache[key]
            return None
        return codes

    def _store(self, key: _CacheKey, codes: frozenset[str]) -> None:
        if self._ttl <= 0:
            return
        now = self._clock()
        self._cache[key] = (now + self._ttl, codes)
        while self._cache and next(iter(self._cache.values()))[0] <= now:
            self._cache.popitem(last=False)
        while len(self._cache) > self._max:
            self._cache.popitem(last=False)
        if self._grace > 0:
            self._last_good[key] = (now + self._ttl, codes)
            self._last_good.move_to_end(key)
            while self._last_good and next(iter(self._last_good.values()))[0] + self._grace <= now:
                self._last_good.popitem(last=False)
            while len(self._last_good) > self._max:
                self._last_good.popitem(last=False)

    def _forget(self, key: _CacheKey) -> None:
        """Core ANSWERED that this caller key is refused (401/403/404): never serve its old answer stale."""
        self._last_good.pop(key, None)

    def _stale(self, key: _CacheKey, exc: PermissionCheckUnavailable) -> tuple[float, frozenset[str]] | None:
        """C4: the held answer for `key` if this failure qualifies and it is inside the grace; else None."""
        if self._grace <= 0:
            return None
        status = getattr(exc, "core_status", None)
        if status is not None and status < 500:  # a malformed 200: Core answered nonsense, not "nothing"
            return None
        entry = self._last_good.get(key)
        if entry is None:
            return None
        if self._clock() >= entry[0] + self._grace:
            return None
        return entry

    def _settled(self, key: _CacheKey, task: asyncio.Task[_Fetched]) -> None:
        if self._inflight.get(key) is task:
            del self._inflight[key]
        if not task.cancelled():
            task.exception()  # mark retrieved: every waiter may have gone away

    # ── Core ──────────────────────────────────────────────────────────────────

    def _http(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                base_url=self._core_url, timeout=self._timeout, transport=self._transport,
                # APP-006: httpx keeps an idle connection for 5 s and uvicorn (Core) closes an idle one after 5 s, so a request could reuse a
                # connection in the instant the server closes it and fail with a reset. Expire ours first.
                limits=httpx.Limits(keepalive_expiry=3.0),
            )
        return self._client

    def _breaker_is_open(self) -> bool:
        return self._breaker_limit > 0 and self._breaker_failures >= self._breaker_limit and self._clock() < self._breaker_open_until

    def _breaker_record(self, outage: bool) -> None:
        if self._breaker_limit <= 0:
            return
        if not outage:
            self._breaker_failures = 0
            self._breaker_open_until = 0.0
            return
        self._breaker_failures += 1
        if self._breaker_failures >= self._breaker_limit:
            if self._clock() >= self._breaker_open_until:
                _log.warning("permission_check_breaker_open", extra={"failures": self._breaker_failures})
            self._breaker_open_until = self._clock() + self._breaker_open_seconds  # also reopens at once when a half-open probe fails

    async def _fetch(self, key: _CacheKey, tenant_id: uuid.UUID, token: str) -> _Fetched:
        """One lookup, plus C3's single retry when the first ask got no answer at all."""
        try:
            return await self._ask(key, tenant_id, token)
        except PermissionCheckUnavailable as exc:
            if not (self._retry and getattr(exc, "no_answer", False)) or self._breaker_is_open():
                raise
        _log.info("permission_check_retry", extra={"tenant_id": str(tenant_id)})
        _count("retried")
        await asyncio.sleep(self._retry_pause)
        return await self._ask(key, tenant_id, token)  # whatever this one gives (answer or failure) is the outcome

    async def _ask(self, key: _CacheKey, tenant_id: uuid.UUID, token: str) -> _Fetched:
        started = time.perf_counter()

        def _elapsed() -> float:
            return round((time.perf_counter() - started) * 1000, 1)

        if self._breaker_is_open():
            _count("breaker_open")
            raise _annotated(PermissionCheckUnavailable(), None, 0.0)

        try:
            resp = await self._http().get(
                PERMISSIONS_PATH,
                headers={
                    # The caller's OWN token: Core authenticates it again and
                    # answers for that caller, so this service cannot ask about
                    # anyone else. The tenant is the signed claim, not input.
                    "Authorization": f"Bearer {token}",
                    "X-Tenant-ID": str(tenant_id),
                    "Accept": "application/json",
                },
            )
        except httpx.HTTPError as exc:
            _log.warning("permission_check_core_unreachable", extra={"error": type(exc).__name__})
            _count("timeout" if isinstance(exc, httpx.TimeoutException) else "unreachable")
            self._breaker_record(outage=True)
            failure = _annotated(PermissionCheckUnavailable(), None, _elapsed())
            failure.no_answer = True  # type: ignore[attr-defined]  # C3 may ask again; an answer never sets this
            raise failure from exc

        latency = _elapsed()
        if resp.status_code in (401, 403, 404):
            self._breaker_record(outage=False)  # Core answered: it is reachable
            self._forget(key)                   # and refused this caller: no stale answer for it from now on
        elif resp.status_code != 200:
            self._breaker_record(outage=True)
        if resp.status_code == 401:
            # Verified locally but refused by Core (revoked session, key rotation
            # not yet seen here). Refuse — never fall through to "allowed".
            _count("unauthorized")
            raise _annotated(InvalidToken(), 401, latency)
        if resp.status_code in (403, 404):
            _count("forbidden")
            raise _annotated(Forbidden("The caller has no access to this tenant"), resp.status_code, latency)
        if resp.status_code != 200:
            _log.warning("permission_check_core_status", extra={"status": resp.status_code})
            _count("server_error")
            raise _annotated(PermissionCheckUnavailable(), resp.status_code, latency)

        try:
            permissions = resp.json()["permissions"]
        except (ValueError, KeyError, TypeError) as exc:
            _log.warning("permission_check_core_malformed")
            _count("malformed")
            self._breaker_record(outage=True)
            raise _annotated(PermissionCheckUnavailable(), resp.status_code, latency) from exc
        if not isinstance(permissions, list) or not all(isinstance(c, str) for c in permissions):
            _log.warning("permission_check_core_malformed")
            _count("malformed")
            self._breaker_record(outage=True)
            raise _annotated(PermissionCheckUnavailable(), resp.status_code, latency)

        self._breaker_record(outage=False)
        _count("ok")
        codes = frozenset(permissions)
        self._store(key, codes)
        return _Fetched(codes=codes, latency_ms=latency)


def _annotated(exc: AuthError, status: int | None, latency_ms: float) -> AuthError:
    """Attach what Core did to a failure, for the warn log. Never part of the response."""
    exc.core_status = status  # type: ignore[attr-defined]
    exc.core_latency_ms = latency_ms  # type: ignore[attr-defined]
    return exc


_checker: _Checker | None = None


def configure_permissions(
    *,
    core_url: str,
    ttl_seconds: float = 30.0,
    timeout_seconds: float = 2.0,
    max_entries: int = 10_000,
    transport: httpx.AsyncBaseTransport | None = None,
    clock: Callable[[], float] = time.monotonic,
    breaker_failures: int = 5,
    breaker_open_seconds: float = 10.0,
    retry_on_no_answer: bool = True,
    retry_pause_seconds: float = 0.15,
    stale_grace_seconds: float = 0.0,
    local_mode: LocalMode | None = None,
    authz_ver_redis_url: str | None = None,
    authz_ver_cache_seconds: float | None = None,
    shadow_log_interval_seconds: float = 60.0,
    authz_ver_redis: object | None = None,
) -> None:
    """Point this service at Core for permission checks. Call once, at startup.

    core_url        Core's base URL (the same host jwks_url points at).
    ttl_seconds     How long one caller's answer is reused. 0 disables caching.
    timeout_seconds Per-request budget for the call to Core; on expiry the check
                    fails closed.
    max_entries     Upper bound on cached callers; the oldest are dropped first.
    transport/clock Test seams (an httpx transport, a monotonic clock).
    breaker_failures  Consecutive Core failures (unreachable, timeout, 5xx, malformed) after which lookups are refused at once, fail-closed, for
                      `breaker_open_seconds`, instead of each waiting out the timeout (APP-007). 0 disables the breaker. A refusal is the same
                      PermissionCheckUnavailable (503) as an unanswered check: never a grant, never cached.
    retry_on_no_answer  C3: ask Core once more, after `retry_pause_seconds`, when the first ask got NO answer (timeout / connection
                        error). Never on an answer (401/403/404/5xx/malformed), never while the breaker is open. Default on; False = off.
    stale_grace_seconds C4: during an outage (no answer, 5xx, breaker open) reuse this process's last successful answer for the same
                        caller key for up to this many seconds past its TTL. 0 (default) = off. Capped at MAX_STALE_GRACE_SECONDS (120);
                        a larger value is clamped with a warning. Needs ttl_seconds > 0. Never on routes marked admin=True.
                        Services read it from PERMISSION_CHECK_STALE_GRACE_SECONDS; enabling it is an owner decision (OD-DEP-1).

    0.6.0 -- local evaluation from access token v2 (module docstring, "Local evaluation"); every default = 0.5.x:
    local_mode          "off" | "shadow" | "local". None -> env PERMISSION_LOCAL_MODE -> "off". An invalid value raises
                        ValueError. "off" builds nothing and changes nothing.
    authz_ver_redis_url Redis to read Core's `authctx:authz_ver` from: the Redis Core's API writes to (Core's
                        REDIS_URL). None -> env PERMISSION_AUTHZ_VER_REDIS_URL -> the client configure_session_revocation()
                        set up (today that is the same Redis, db 0). None of them -> every check falls back
                        (authz_ver_not_configured). Needs the redis package (extra `session-revocation`).
    authz_ver_cache_seconds  How long this process reuses the authz_ver it read (also a failed read). None -> env
                        PERMISSION_AUTHZ_VER_CACHE_SECONDS -> 2. Clamped to 0..5.
    shadow_log_interval_seconds  Rate limit of the shadow / fallback log lines per (outcome, reason, permission).
    authz_ver_redis     Test seam: an object with `async get(key)` used instead of a URL.
    """
    global _checker
    if not core_url or not core_url.strip():
        raise ValueError("core_url is required")
    if ttl_seconds < 0:
        raise ValueError("ttl_seconds must be >= 0")
    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be > 0")
    if max_entries < 1:
        raise ValueError("max_entries must be >= 1")
    if breaker_failures < 0 or breaker_open_seconds <= 0:
        raise ValueError("breaker_failures must be >= 0 and breaker_open_seconds > 0")
    if retry_pause_seconds < 0:
        raise ValueError("retry_pause_seconds must be >= 0")
    if stale_grace_seconds < 0:
        raise ValueError("stale_grace_seconds must be >= 0")
    if stale_grace_seconds > MAX_STALE_GRACE_SECONDS:
        _log.warning(
            "permission_stale_grace_clamped",
            extra={"configured": stale_grace_seconds, "max": MAX_STALE_GRACE_SECONDS},
        )
    if local_mode is None:
        local_mode = (os.environ.get(ENV_LOCAL_MODE, "").strip().lower() or "off")  # type: ignore[assignment]
    if local_mode not in LOCAL_MODES:
        raise ValueError(f"local_mode must be one of {LOCAL_MODES}, got {local_mode!r}")
    if shadow_log_interval_seconds < 0:
        raise ValueError("shadow_log_interval_seconds must be >= 0")
    local: LocalEvaluator | None = None
    if local_mode != "off":
        cache_seconds = authz_ver_cache_seconds if authz_ver_cache_seconds is not None else env_cache_seconds()
        if cache_seconds is None:
            cache_seconds = DEFAULT_AUTHZ_VER_CACHE_SECONDS
        if cache_seconds < 0:
            raise ValueError("authz_ver_cache_seconds must be >= 0")
        if cache_seconds > MAX_AUTHZ_VER_CACHE_SECONDS:
            _log.warning(
                "permission_authz_ver_cache_clamped",
                extra={"configured": cache_seconds, "max": MAX_AUTHZ_VER_CACHE_SECONDS},
            )
        local = LocalEvaluator(
            core_url=core_url, timeout_seconds=timeout_seconds, transport=transport, clock=clock,
            redis=authz_ver_redis,
            redis_url=authz_ver_redis_url or os.environ.get(ENV_REDIS_URL, "").strip() or None,
            authz_ver_cache_seconds=cache_seconds,
        )
        _log.info("permission_local_mode", extra={"local_mode": local_mode})
    _checker = _Checker(
        local=local,
        local_mode=local_mode,
        shadow_log_interval_seconds=shadow_log_interval_seconds,
        core_url=core_url,
        ttl_seconds=ttl_seconds,
        timeout_seconds=timeout_seconds,
        max_entries=max_entries,
        transport=transport,
        clock=clock,
        breaker_failures=breaker_failures,
        breaker_open_seconds=breaker_open_seconds,
        retry_on_no_answer=retry_on_no_answer,
        retry_pause_seconds=retry_pause_seconds,
        stale_grace_seconds=stale_grace_seconds,
    )


async def aclose_permissions() -> None:
    """Close the connection to Core. Call from the app's shutdown hook."""
    if _checker is not None:
        await _checker.aclose()


def reset_permissions() -> None:
    """Drop the permission configuration and its cache. Tests only."""
    global _checker
    _checker = None


def require_permission(code: str, *, mode: Mode = "enforce", admin: bool = False) -> Callable[..., object]:
    """Restrict a route to callers whose role holds exactly this permission code.

    One code, deliberately: a route has one deterministic permission. Returns the
    verified AuthContext unchanged, so it can replace an existing dependency of
    the same shape.

    mode="enforce" (default) refuses a caller who lacks the code (403), whose token
    Core rejects (401/403), or when Core cannot answer (503).
    mode="warn" performs the same check and refuses nothing; see the module
    docstring.
    admin=True marks an administrative / role-management / break-glass route: it is
    never answered from C4's stale-on-error cache, whatever stale_grace_seconds says.
    """
    if not isinstance(code, str) or not code or any(ch.isspace() for ch in code):
        raise ValueError(f"permission code must be a non-empty string without spaces, got {code!r}")
    if mode not in ("enforce", "warn"):
        raise ValueError(f"mode must be 'enforce' or 'warn', got {mode!r}")

    async def _check(
        request: Request,
        ctx: Annotated[AuthContext, Depends(require_tenant)],
        credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)] = None,
    ) -> AuthContext:
        if admin:
            # Same notion, one more consumer: check_session_revocation treats an admin route as sensitive
            # (fail_mode="split": fail closed, no cached status). Only seen by a revocation dependency that
            # runs AFTER this one; use session_revocation_check(sensitive=True) for an order-independent mark.
            request.state.blumax_sensitive_route = True
        if ctx.is_platform_admin:
            if mode == "warn":
                _emit(request, ctx, code, decision="allow", reason="platform_admin", cached=False)
            return ctx
        if credentials is None:  # require_tenant would already have refused; belt and braces
            raise MissingCredentials()

        checker = _checker
        if checker is None:
            if mode == "warn":
                _emit(request, ctx, code, decision="check_failed", reason="not_configured", cached=False)
                return ctx
            raise RuntimeError("blumax_auth.configure_permissions() has not been called")

        try:
            allowed, answer = await _decide(
                checker, ctx, credentials.credentials, code, admin=admin, route=_route_of(request),
            )
        except AuthError as exc:
            if mode == "warn":
                _emit(
                    request, ctx, code, decision="check_failed", reason=_reason_for(exc),
                    cached=False,
                    core_latency_ms=getattr(exc, "core_latency_ms", None),
                    core_status=getattr(exc, "core_status", None),
                )
                return ctx
            raise
        except Exception:
            if mode == "warn":
                _log.exception("permission_check_error")
                _emit(request, ctx, code, decision="check_failed", reason="error", cached=False)
                return ctx
            raise

        if allowed:
            if mode == "warn":
                _emit(
                    request, ctx, code, decision="allow", cached=answer.cached,
                    core_latency_ms=answer.latency_ms, source=answer.source,
                )
            return ctx
        if mode == "warn":
            _emit(
                request, ctx, code, decision="would_deny", reason="missing_permission",
                cached=answer.cached, core_latency_ms=answer.latency_ms, source=answer.source,
            )
            return ctx
        raise Forbidden(f"Requires permission: {code}")

    return _check


async def check_permission(ctx: AuthContext, token: str, code: str, *, admin: bool = False) -> bool:
    """Whether `ctx`'s role holds `code`, per Core — for a check that can't be
    expressed as a route-level `require_permission()` dependency because
    whether it applies at all depends on something only known once the
    request body is parsed (e.g. an `emergency_override: bool` field), not
    just on which route was hit.

    Same source of truth as `require_permission()` (Core's own
    GET /api/v1/me/permissions, cached the same way) — just returned as a
    bool instead of raising, so the caller decides what "no" means for that
    one call site, including its own warn/enforce rollout mode if it wants
    one.

    Raises the same `AuthError` subclasses `require_permission()`'s
    dependency does when Core can't be asked at all (unreachable, malformed
    response, `configure_permissions()` never called) — a caller that wants
    warn-mode semantics (log and allow) should catch `AuthError` itself, the
    same way `require_permission(mode="warn")` does internally.

    admin=True: never answered from the stale-on-error cache (see require_permission).
    """
    if ctx.is_platform_admin:
        return True
    checker = _checker
    if checker is None:
        raise RuntimeError("blumax_auth.configure_permissions() has not been called")
    allowed, _ = await _decide(checker, ctx, token, code, admin=admin, route=None)
    return allowed


async def _decide(
    checker: _Checker, ctx: AuthContext, token: str, code: str, *, admin: bool, route: str | None,
) -> tuple[bool, _Answer]:
    """(allowed, how it was decided). With local_mode "off" this is exactly `code in Core's answer`."""
    local = checker.local
    if local is None or checker.local_mode == "off":
        answer = await _granted(checker, ctx, token, admin=admin)
        return code in answer.codes, answer

    if checker.local_mode == "local":
        # An admin / role-management / break-glass route never takes the token's answer: the up-to-5 s authz_ver cache
        # is a staleness window those routes must not have (same spirit as "never stale-served" for C4).
        decision = LocalDecision(granted=None, reason="admin_route") if admin else await local.evaluate(ctx, token, code)
        if decision.granted is not None:
            checker.note_local(
                "permission_local_decision", ctx, code, decision,
                outcome="local_allow" if decision.granted else "local_deny", route=route,
            )
            return decision.granted, _Answer(codes=frozenset(), cached=True, source="local")
        checker.note_local("permission_local_fallback", ctx, code, decision, outcome=f"fallback:{decision.reason}", route=route)
        answer = await _granted(checker, ctx, token, admin=admin)
        return code in answer.codes, answer

    # shadow: Core decides (a Core failure propagates exactly as in "off" and nothing is compared).
    answer = await _granted(checker, ctx, token, admin=admin)
    allowed = code in answer.codes
    try:
        decision = await local.evaluate(ctx, token, code)
        if decision.granted is None:
            outcome = f"fallback:{decision.reason}"
        else:
            outcome = "match" if decision.granted == allowed else "mismatch"
        checker.note_local("permission_local_shadow", ctx, code, decision, outcome=outcome, route=route, core_decision=allowed)
    except Exception:  # shadow work must never change the request
        _log.exception("permission_local_shadow_error")
    return allowed, answer


def _route_of(request: Request) -> str | None:
    route = request.scope.get("route")
    return getattr(route, "path", None)


async def _granted(checker: _Checker, ctx: AuthContext, token: str, *, admin: bool) -> _Answer:
    # The keyword is passed only when it matters, so a service that still wraps `granted(ctx, token)` (IPD's / OPD's
    # app/core/permission_resilience.py, written against 0.5.1) keeps working unchanged on 0.5.2 for non-admin routes.
    if admin:
        return await checker.granted(ctx, token, allow_stale=False)
    return await checker.granted(ctx, token)


def _reason_for(exc: AuthError) -> str:
    if isinstance(exc, PermissionCheckUnavailable):
        return "core_unavailable"
    if isinstance(exc, InvalidToken):
        return "core_rejected_token"
    if isinstance(exc, Forbidden):
        return "core_forbidden"
    return "error"


def _emit(
    request: Request,
    ctx: AuthContext,
    code: str,
    *,
    decision: str,
    cached: bool,
    reason: str | None = None,
    core_latency_ms: float | None = None,
    core_status: int | None = None,
    source: str = "core",
) -> None:
    """One `permission_check` event. Plain scalars only: no token, no permission list.

    The route is the TEMPLATE the router matched (/opd/visits/{visit_id}/cancel), so
    a log line never carries a concrete id. If no route matched there is no honest
    template to report, and the concrete path is NOT substituted for it.
    """
    route = request.scope.get("route")
    extra: dict[str, object] = {
        "decision": decision,
        "mode": "warn",
        "permission": code,
        "route": getattr(route, "path", None) or "<unmatched>",
        "method": request.method,
        "tenant_id": str(ctx.tenant_id),
        "user_id": str(ctx.user_id),
        "role": ctx.role,
        "archetype": ctx.archetype,
        "is_service": ctx.is_service,
        "cached": cached,
    }
    if reason is not None:
        extra["reason"] = reason
    if core_latency_ms is not None:
        extra["core_latency_ms"] = core_latency_ms
    if core_status is not None:
        extra["core_status"] = core_status
    if source != "core":  # only local decisions (local_mode="local") add the field; Core-path lines are unchanged
        extra["source"] = source
    _log.log(logging.INFO if decision == "allow" else logging.WARNING, "permission_check", extra=extra)
