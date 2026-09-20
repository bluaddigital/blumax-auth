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

_log = logging.getLogger("blumax_auth.permissions")

#: Core's endpoint for "what does this caller hold?".
PERMISSIONS_PATH = "/api/v1/me/permissions"

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
    ) -> None:
        self._core_url = core_url.rstrip("/")
        self._ttl = ttl_seconds
        self._timeout = timeout_seconds
        self._max = max_entries
        self._transport = transport
        self._clock = clock
        self._client: httpx.AsyncClient | None = None
        # Insertion order == expiry order (one constant TTL), so expired entries
        # are always at the front and eviction is a cheap popitem.
        self._cache: OrderedDict[_CacheKey, tuple[float, frozenset[str]]] = OrderedDict()
        self._inflight: dict[_CacheKey, asyncio.Task[_Fetched]] = {}

    # ── public ────────────────────────────────────────────────────────────────

    async def granted(self, ctx: AuthContext, token: str) -> _Answer:
        """The codes Core says this caller holds in the token's tenant."""
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
        fetched = await asyncio.shield(task)
        return _Answer(codes=fetched.codes, cached=False, latency_ms=fetched.latency_ms)

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    def clear(self) -> None:
        self._cache.clear()

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
            )
        return self._client

    async def _fetch(self, key: _CacheKey, tenant_id: uuid.UUID, token: str) -> _Fetched:
        started = time.perf_counter()

        def _elapsed() -> float:
            return round((time.perf_counter() - started) * 1000, 1)

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
            raise _annotated(PermissionCheckUnavailable(), None, _elapsed()) from exc

        latency = _elapsed()
        if resp.status_code == 401:
            # Verified locally but refused by Core (revoked session, key rotation
            # not yet seen here). Refuse — never fall through to "allowed".
            raise _annotated(InvalidToken(), 401, latency)
        if resp.status_code in (403, 404):
            raise _annotated(Forbidden("The caller has no access to this tenant"), resp.status_code, latency)
        if resp.status_code != 200:
            _log.warning("permission_check_core_status", extra={"status": resp.status_code})
            raise _annotated(PermissionCheckUnavailable(), resp.status_code, latency)

        try:
            permissions = resp.json()["permissions"]
        except (ValueError, KeyError, TypeError) as exc:
            _log.warning("permission_check_core_malformed")
            raise _annotated(PermissionCheckUnavailable(), resp.status_code, latency) from exc
        if not isinstance(permissions, list) or not all(isinstance(c, str) for c in permissions):
            _log.warning("permission_check_core_malformed")
            raise _annotated(PermissionCheckUnavailable(), resp.status_code, latency)

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
) -> None:
    """Point this service at Core for permission checks. Call once, at startup.

    core_url        Core's base URL (the same host jwks_url points at).
    ttl_seconds     How long one caller's answer is reused. 0 disables caching.
    timeout_seconds Per-request budget for the call to Core; on expiry the check
                    fails closed.
    max_entries     Upper bound on cached callers; the oldest are dropped first.
    transport/clock Test seams (an httpx transport, a monotonic clock).
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
    _checker = _Checker(
        core_url=core_url,
        ttl_seconds=ttl_seconds,
        timeout_seconds=timeout_seconds,
        max_entries=max_entries,
        transport=transport,
        clock=clock,
    )


async def aclose_permissions() -> None:
    """Close the connection to Core. Call from the app's shutdown hook."""
    if _checker is not None:
        await _checker.aclose()


def reset_permissions() -> None:
    """Drop the permission configuration and its cache. Tests only."""
    global _checker
    _checker = None


def require_permission(code: str, *, mode: Mode = "enforce") -> Callable[..., object]:
    """Restrict a route to callers whose role holds exactly this permission code.

    One code, deliberately: a route has one deterministic permission. Returns the
    verified AuthContext unchanged, so it can replace an existing dependency of
    the same shape.

    mode="enforce" (default) refuses a caller who lacks the code (403), whose token
    Core rejects (401/403), or when Core cannot answer (503).
    mode="warn" performs the same check and refuses nothing; see the module
    docstring.
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
            answer = await checker.granted(ctx, credentials.credentials)
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
