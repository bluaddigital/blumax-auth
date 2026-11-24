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

Role map (0.6.0, OFF unless role_map=True / BLUMAX_PERMISSION_ROLE_MAP=true)
--------------------------------------------------------------------------
Core (PERMISSION_VERSION_CLAIMS_ENABLED) can put two more claims in an access token: `rid`, the caller's role ids, and `pv`, its
tenant's permission version. Database triggers in Core bump that version on EVERY write that can change who holds which role (membership
created / removed / role changed / deactivated, additional role granted / removed, user deactivated or forced to change password, tenant
suspended), and a separate global grants version on every role-permission write. Core copies both to Redis (sorted set
`role:perms:ver`, member = tenant id / "grants") about once a second.

With the switch on, a check for a token that carries both claims goes:
  1. session not revoked: session_revocation's Redis check (exempt jti / marker), reused <= version_cache_seconds. Revoked, Redis
     unavailable or a malformed marker -> ask Core (which answers 401 for a revoked session).
  2. ZMSCORE role:perms:ver <tenant> grants, reused per tenant for <= version_cache_seconds (max 5 s).
  3. token pv == the tenant's published pv, else ask Core (the token predates a membership change).
  4. codes for each role in `rid` from a per-process map keyed (tenant, grants version), fetched from Core's
     GET /api/v1/identity/role-permissions (with the caller's own token, If-None-Match) once per new grants version / new role; Core also
     returns the database's current pv, and a mismatch there means "ask Core".
  5. union of those codes -> the same allow / deny the old path gives.
Any other outcome -- claims missing or malformed, a service token, session revocation not configured, Redis down or refusing (ACL),
a version missing, an unknown role, Core's endpoint failing -- is a FALLBACK to the old path above (C1-C4 unchanged), never a grant.
Platform admins pass before any of this, as before. A revoked role / membership / grant therefore stops working within Core's publish
interval (~1 s) + version_cache_seconds (<= 5 s), even for a token minted before the change. Needs configure_session_revocation():
that is the shared Redis the versions are read from. Counters: role_map_hit / role_map_fallback / role_map_fetch.

Counters (optional): `blumax_core_permission_calls_total{outcome}` when the process
has BLUMAX_METRICS_ENABLED=true and prometheus_client installed; see metrics.py.
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
from blumax_auth.metrics import core_permission_call as _count

_log = logging.getLogger("blumax_auth.permissions")

#: Core's endpoint for "what does this caller hold?".
PERMISSIONS_PATH = "/api/v1/me/permissions"

#: Hard upper bound for C4's grace (a larger configured value is clamped to it).
MAX_STALE_GRACE_SECONDS = 120.0

#: 0.6.0 role map: Core's role -> codes endpoint, the Redis sorted set Core publishes the versions to, and its grants member.
ROLE_PERMISSIONS_PATH = "/api/v1/identity/role-permissions"
VERSIONS_KEY = "role:perms:ver"
GRANTS_MEMBER = "grants"
#: Upper bound for how long a tenant's published versions are reused (the revocation window on top of Core's ~1 s publish).
MAX_VERSION_CACHE_SECONDS = 5.0
#: Environment switch read when configure_permissions(role_map=None).
ROLE_MAP_ENV = "BLUMAX_PERMISSION_ROLE_MAP"

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
        role_map: bool = False,
        version_cache_seconds: float = MAX_VERSION_CACHE_SECONDS,
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
        # 0.6.0 role map (off unless role_map=True). See "Role map" in the module docstring.
        self._role_map = role_map
        self._version_ttl = min(max(0.0, version_cache_seconds), MAX_VERSION_CACHE_SECONDS)
        # tenant -> (expires_at, tenant pv, grants gv); a failed read is never stored.
        self._versions: dict[uuid.UUID, tuple[float, int, int]] = {}
        self._versions_inflight: dict[uuid.UUID, asyncio.Task[tuple[int, int] | None]] = {}
        # (tenant, gv) -> {role id: codes}. Only the newest gv per tenant is kept.
        self._role_codes: OrderedDict[tuple[uuid.UUID, int], dict[uuid.UUID, frozenset[str]]] = OrderedDict()
        # (tenant, role set) -> (etag, {role id: codes}) of the last 200, for If-None-Match.
        self._role_etags: OrderedDict[tuple[uuid.UUID, tuple[uuid.UUID, ...]], tuple[str, dict[uuid.UUID, frozenset[str]]]] = OrderedDict()
        self._map_inflight: dict[tuple[uuid.UUID, int, tuple[uuid.UUID, ...]], asyncio.Task[dict[uuid.UUID, frozenset[str]] | None]] = {}
        # (user, jti) -> expires_at: "this session was not revoked" as read from Redis, reused for at most the version TTL.
        self._not_revoked: OrderedDict[tuple[uuid.UUID, str], float] = OrderedDict()

    # ── public ────────────────────────────────────────────────────────────────

    async def granted(self, ctx: AuthContext, token: str, *, allow_stale: bool = True) -> _Answer:
        """The codes Core says this caller holds in the token's tenant.

        allow_stale=False (routes marked admin) never takes C4's stale answer.
        """
        assert ctx.tenant_id is not None  # require_tenant() guarantees it
        if self._role_map:
            mapped = await self._from_role_map(ctx, token)
            if mapped is not None:
                return mapped
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
        self._versions.clear()
        self._role_codes.clear()
        self._role_etags.clear()
        self._not_revoked.clear()

    # ── 0.6.0 role map ────────────────────────────────────────────────────────

    async def _from_role_map(self, ctx: AuthContext, token: str) -> _Answer | None:
        """The caller's codes from the role -> codes map, or None = "not usable for this request, ask Core the old way".

        Every step that is not a clear yes returns None; nothing here ever raises into the request and nothing here ever grants
        what Core's own answer would not. Steps: claims present -> session not revoked (Redis) -> token pv == the tenant's
        published pv (Redis, <= version TTL old) -> every role of the token in the map for the current grants version (fetched
        from Core once per version) -> union."""
        reason = await self._role_map_reason(ctx)
        if reason is not None:
            return self._fallback(ctx, reason)
        assert ctx.tenant_id is not None and ctx.role_ids is not None
        try:
            versions = await self._tenant_versions(ctx.tenant_id)
        except Exception:  # noqa: BLE001 - any doubt is a fallback
            versions = None
        if versions is None:
            return self._fallback(ctx, "versions_unavailable")
        pv, gv = versions
        if ctx.roles_version != pv:
            return self._fallback(ctx, "pv_mismatch")
        known = self._role_codes.get((ctx.tenant_id, gv), {})
        missing = tuple(r for r in ctx.role_ids if r not in known)
        fetched = False
        if missing:
            try:
                got = await self._role_codes_from_core(ctx.tenant_id, gv, ctx.role_ids, token, pv)
            except Exception:  # noqa: BLE001
                got = None
            if got is None:
                return self._fallback(ctx, "role_map_unavailable")
            known = got
            fetched = True
        if any(r not in known for r in ctx.role_ids):
            return self._fallback(ctx, "unknown_role")
        codes: set[str] = set()
        for role_id in ctx.role_ids:
            codes |= known[role_id]
        _count("role_map_hit")
        return _Answer(codes=frozenset(codes), cached=not fetched)

    async def _role_map_reason(self, ctx: AuthContext) -> str | None:
        """Why this request cannot use the role map (None = it may, so far)."""
        if ctx.role_ids is None or ctx.roles_version is None or ctx.is_service:
            return "no_claims"
        from blumax_auth import (
            session_revocation,  # noqa: PLC0415 - avoids an import cycle at module load
        )

        revocation = session_revocation._checker
        if revocation is None:
            # The shared Redis is how both the versions and the revocation markers are read. Without it, Core's own answer is the
            # only one that also covers a logged-out session, so ask Core.
            return "no_redis"
        if ctx.jti is None or ctx.issued_at is None:
            return "no_session_identity"
        key = (ctx.user_id, ctx.jti)
        now = self._clock()
        until = self._not_revoked.get(key)
        if until is not None and now < until:
            return None
        try:
            revoked, ambiguous, _ = await revocation.is_revoked(ctx.user_id, ctx.issued_at, ctx.jti)
        except Exception:  # noqa: BLE001
            return "revocation_unavailable"
        if revoked:
            return "session_revoked"          # Core will answer 401 on the old path
        if ambiguous is not None:
            return "revocation_unavailable"   # Redis down / marker malformed: never treated as "not revoked" here
        if self._version_ttl > 0:
            self._not_revoked[key] = now + self._version_ttl
            self._not_revoked.move_to_end(key)
            while len(self._not_revoked) > self._max:
                self._not_revoked.popitem(last=False)
        return None

    def _fallback(self, ctx: AuthContext, reason: str) -> None:
        _count("role_map_fallback")
        _log.debug("permission_role_map_fallback", extra={"reason": reason, "tenant_id": str(ctx.tenant_id)})
        return None

    async def _tenant_versions(self, tenant_id: uuid.UUID) -> tuple[int, int] | None:
        """(tenant pv, grants gv) as Core last published them, reused for at most the version TTL. None on any doubt."""
        entry = self._versions.get(tenant_id)
        if entry is not None and self._clock() < entry[0]:
            return entry[1], entry[2]
        task = self._versions_inflight.get(tenant_id)
        if task is None:
            task = asyncio.ensure_future(self._read_versions(tenant_id))
            self._versions_inflight[tenant_id] = task

            def _done(t: asyncio.Task, k: uuid.UUID = tenant_id) -> None:
                if self._versions_inflight.get(k) is t:
                    del self._versions_inflight[k]
                if not t.cancelled():
                    t.exception()

            task.add_done_callback(_done)
        return await asyncio.shield(task)

    async def _read_versions(self, tenant_id: uuid.UUID) -> tuple[int, int] | None:
        from blumax_auth import session_revocation  # noqa: PLC0415

        revocation = session_revocation._checker
        if revocation is None:
            return None
        try:
            scores = await asyncio.wait_for(
                revocation.redis.zmscore(VERSIONS_KEY, [str(tenant_id), GRANTS_MEMBER]), session_revocation._redis_timeout(),
            )
        except Exception:  # noqa: BLE001 - Redis down, ACL refusal, timeout: ask Core
            _log.warning("permission_role_map_versions_unavailable", extra={"tenant_id": str(tenant_id)})
            return None
        if not scores or len(scores) != 2 or scores[0] is None or scores[1] is None:
            return None
        try:
            pv, gv = int(scores[0]), int(scores[1])
        except (TypeError, ValueError):
            return None
        if self._version_ttl > 0:
            self._versions[tenant_id] = (self._clock() + self._version_ttl, pv, gv)
            if len(self._versions) > self._max:
                self._versions.pop(next(iter(self._versions)))
        return pv, gv

    async def _role_codes_from_core(
        self, tenant_id: uuid.UUID, gv: int, role_ids: tuple[uuid.UUID, ...], token: str, pv: int,
    ) -> dict[uuid.UUID, frozenset[str]] | None:
        """Fetch codes for `role_ids` (single-flight per tenant + version + role set) and merge them into the map for (tenant, gv).
        Returns the merged map, or None (not stored) on any doubt."""
        fkey = (tenant_id, gv, role_ids)
        task = self._map_inflight.get(fkey)
        if task is None:
            task = asyncio.ensure_future(self._fetch_role_codes(tenant_id, gv, role_ids, token, pv))
            self._map_inflight[fkey] = task

            def _done(t: asyncio.Task, k=fkey) -> None:
                if self._map_inflight.get(k) is t:
                    del self._map_inflight[k]
                if not t.cancelled():
                    t.exception()

            task.add_done_callback(_done)
        return await asyncio.shield(task)

    async def _fetch_role_codes(
        self, tenant_id: uuid.UUID, gv: int, role_ids: tuple[uuid.UUID, ...], token: str, pv: int,
    ) -> dict[uuid.UUID, frozenset[str]] | None:
        _count("role_map_fetch")
        ekey = (tenant_id, role_ids)
        previous = self._role_etags.get(ekey)
        headers = {
            # The caller's OWN token: Core lets a user token ask only about the roles its own `rid` names. Tenant = the signed claim.
            "Authorization": f"Bearer {token}",
            "X-Tenant-ID": str(tenant_id),
            "Accept": "application/json",
        }
        if previous is not None:
            headers["If-None-Match"] = previous[0]
        resp = await self._http().get(ROLE_PERMISSIONS_PATH, params={"role_ids": ",".join(str(r) for r in role_ids)}, headers=headers)
        try:
            core_gv = int(resp.headers["X-Grant-Version"])
            core_pv = int(resp.headers["X-Permission-Version"])
        except (KeyError, ValueError):
            return None
        if resp.status_code == 304 and previous is not None:
            roles = previous[1]
        elif resp.status_code == 200:
            try:
                body = resp.json()
                raw = body["roles"]
                if not isinstance(raw, dict):
                    return None
                roles = {}
                for rid, codes in raw.items():
                    if not isinstance(codes, list) or not all(isinstance(c, str) for c in codes):
                        return None
                    roles[uuid.UUID(rid)] = frozenset(codes)
            except (ValueError, KeyError, TypeError):
                return None
            etag = resp.headers.get("ETag")
            if etag:
                self._role_etags[ekey] = (etag, roles)
                self._role_etags.move_to_end(ekey)
                while len(self._role_etags) > self._max:
                    self._role_etags.popitem(last=False)
        else:
            return None
        # Core read these codes AFTER its versions, so they are at least as new as `core_gv`. Core's database being BEHIND what Redis
        # said cannot happen in a sane deployment (Redis is a copy): treat it as doubt and keep nothing.
        if core_gv < gv:
            return None
        if core_pv != pv:
            # The database already moved past the token's version (Redis has not caught up yet): this token is out of date.
            # The codes are still right for these roles, but the caller must not be answered from them.
            self._merge_role_codes(tenant_id, gv, roles)
            return None
        return self._merge_role_codes(tenant_id, gv, roles)

    def _merge_role_codes(
        self, tenant_id: uuid.UUID, gv: int, roles: dict[uuid.UUID, frozenset[str]],
    ) -> dict[uuid.UUID, frozenset[str]]:
        key = (tenant_id, gv)
        for old in [k for k in self._role_codes if k[0] == tenant_id and k[1] != gv]:
            del self._role_codes[old]   # an older grants version of this tenant is never read again
        merged = {**self._role_codes.get(key, {}), **roles}
        self._role_codes[key] = merged
        self._role_codes.move_to_end(key)
        while len(self._role_codes) > self._max:
            self._role_codes.popitem(last=False)
        return merged

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
    role_map: bool | None = None,
    version_cache_seconds: float = MAX_VERSION_CACHE_SECONDS,
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
    role_map        0.6.0: resolve a token's `rid` + `pv` from a per-process role -> codes map instead of asking Core per caller
                    (see "Role map" in the module docstring). None (default) = read env BLUMAX_PERMISSION_ROLE_MAP ("true"/"1"/"on");
                    unset = OFF, exactly 0.5.2's behaviour. Needs configure_session_revocation() (the shared Redis); without it every
                    request simply takes the old path.
    version_cache_seconds  How long a tenant's published versions are reused (default and maximum 5; larger is clamped).
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
    if role_map is None:
        role_map = os.environ.get(ROLE_MAP_ENV, "").strip().lower() in ("1", "true", "yes", "on")
    if version_cache_seconds < 0:
        raise ValueError("version_cache_seconds must be >= 0")
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
        role_map=role_map,
        version_cache_seconds=version_cache_seconds,
    )
    if role_map:
        _log.info("permission_role_map_enabled", extra={"version_cache_seconds": min(version_cache_seconds, MAX_VERSION_CACHE_SECONDS)})


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
