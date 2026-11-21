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
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
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
from blumax_auth.metrics import core_permission_call as _count

_log = logging.getLogger("blumax_auth.permissions")

#: Core's endpoint for "what does this caller hold?".
PERMISSIONS_PATH = "/api/v1/me/permissions"

#: Hard upper bound for C4's grace (a larger configured value is clamped to it).
MAX_STALE_GRACE_SECONDS = 120.0

Mode = Literal["enforce", "warn"]
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
    ) -> None:
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
    _checker = _Checker(
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
            answer = await _granted(checker, ctx, credentials.credentials, admin=admin)
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

        if code in answer.codes:
            if mode == "warn":
                _emit(
                    request, ctx, code, decision="allow", cached=answer.cached,
                    core_latency_ms=answer.latency_ms,
                )
            return ctx
        if mode == "warn":
            _emit(
                request, ctx, code, decision="would_deny", reason="missing_permission",
                cached=answer.cached, core_latency_ms=answer.latency_ms,
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
    answer = await _granted(checker, ctx, token, admin=admin)
    return code in answer.codes


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
    _log.log(logging.INFO if decision == "allow" else logging.WARNING, "permission_check", extra=extra)
