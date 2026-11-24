"""Local permission evaluation from access token v2 (0.6.0) -- used by permissions.py only when local_mode != "off".

Access token v2 (Core TOKEN_PROFILE=v2; blumax-backend app/core/access_token_v2.py) carries the caller's EFFECTIVE
permissions in the token's tenant -- exactly what GET /api/v1/me/permissions answers -- as

    perm      = {"cv": <catalogue version>, "b": <base64url bitset>}   bit idx set <=> the code with that idx is held
    authz_ver = <Core's global authorization version when the token was minted>

This module answers "does this token hold `code`?" from those two claims, or says WHY it cannot (a fallback reason), in
which case the caller asks Core exactly as before. It never grants or denies on doubt: every condition below that is not
met is a fallback, never a "no".

The answer is usable only when ALL of these hold (checked in this order; the first failure is the fallback reason):

  1. the token is a staff access token v2 (`ver: 2`, `type: "access"`), or  else v1_token / service_token
     (0.6.4) a SCOPED service token (`ver: 2`, `type: "service"`, a `perm` claim -- Core
     SERVICE_TOKEN_SCOPES=enforce); an unscoped service token is service_token
     (its claims are re-read from the SAME token require_tenant() just verified; sub/tid must match the context,
     else token_unreadable)
  2. it carries a well-formed `perm` claim                                    else no_perm
  3. it carries an integer `authz_ver`                                        else no_authz_ver
  4. FRESHNESS -- Core's current authz_ver, read from Redis key `authctx:authz_ver` (the Redis Core's API writes it
     to: Core's REDIS_URL), through a per-process cache of at most 5 s, EQUALS the token's value. Compared with `!=`,
     not `<`: a flushed Redis restarts the counter at 0.
       no Redis configured                                                    authz_ver_not_configured
       Redis error / timeout / ACL refusal (NOPERM)                           authz_ver_unavailable
       key absent (flushed Redis, or this service reads a different Redis
       or db than Core writes -- Core itself would mint 0 here, so a token
       minted before the first bump also falls back until one happens)       authz_ver_unset
       token value != current (an authorization write since the token was
       minted: role edit, role assignment, membership/facility change, ...)   authz_ver_stale
     Bounded staleness when the answer IS used: an authorization write is seen at the latest after the cache window
     (authz_ver_cache_seconds, default 2 s, clamped to 5 s).
  5. the catalogue (Core GET /api/v1/authz/catalogue: version + ordered {idx, code, status}) is held at a version
     >= the token's cv. It is PRELOADED in the background: the first staff v2 token this process sees (or the first
     naming a newer cv) starts ONE fetch, with that caller's own token (Core accepts any authenticated staff or service
     token; there is no token to fetch with before the first request), and NO request ever waits for it -- requests
     fall back until it has landed. The preload is started before the freshness check, so a stale / unset authz_ver
     does not keep the catalogue from loading. Cached per version. One fetch at a time per process (single-flight); a
     failed fetch is not retried for `catalogue_retry_seconds` (10 s), a fetch that returned an older version than
     wanted not for 5 s. Its own timeout: `catalogue_timeout_seconds` (env PERMISSION_CATALOGUE_TIMEOUT_SECONDS,
     default 10, capped at 30) -- independent of the permission-check timeout, because the catalogue is a one-off
     ~30 KB read that a busy Core can take seconds to serve.
       no catalogue yet, the preload is in flight                            catalogue_loading
       no catalogue: the fetch failed / was malformed (backing off)          catalogue_unavailable
       held catalogue older than the token's cv (refetch in the background)  catalogue_behind
  6. the bitset decodes (base64url, every set bit names an index the catalogue has)   else invalid_bitset
     (Core's own decode also refuses a bit introduced after cv; the catalogue endpoint does not publish
     introduced_in, so that one check is not repeated here -- Core never sets such a bit, and the token is signed.)
  7. the code being checked is in the catalogue (active or deprecated)       else unknown_code

Bitset format (blumax-backend app/core/permission_index.py pack_indexes/unpack_indexes, mirrored exactly): bit i lives
in byte i // 8 at position i % 8 (LSB first), trailing zero bytes trimmed, base64url without padding, "" = no codes.

Platform admins never reach this module (require_permission/check_permission pass them first, unchanged). An unscoped
service token is a fallback (service_token) and keeps today's Core path; a scoped one (G8) is answered from its `perm`.
A delegated token (Core token exchange, `act` claim) is a staff access token and needs nothing special: its `perm` is
already the user's permissions INTERSECT the service's scopes.
"""
from __future__ import annotations

import asyncio
import base64
import binascii
import contextlib
import logging
import os
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import httpx
from jose import JWTError, jwt

from blumax_auth.context import AuthContext

_log = logging.getLogger("blumax_auth.permissions")

CATALOGUE_PATH = "/api/v1/authz/catalogue"
AUTHZ_VER_KEY = "authctx:authz_ver"

#: Upper bound for the authz_ver cache (the plan's "<= 5 s local cache").
MAX_AUTHZ_VER_CACHE_SECONDS = 5.0
DEFAULT_AUTHZ_VER_CACHE_SECONDS = 2.0
DEFAULT_REDIS_TIMEOUT_SECONDS = 0.5
DEFAULT_CATALOGUE_RETRY_SECONDS = 10.0
CATALOGUE_BEHIND_RETRY_SECONDS = 5.0
DEFAULT_CATALOGUE_TIMEOUT_SECONDS = 10.0
MAX_CATALOGUE_TIMEOUT_SECONDS = 30.0

ENV_REDIS_URL = "PERMISSION_AUTHZ_VER_REDIS_URL"
ENV_CACHE_SECONDS = "PERMISSION_AUTHZ_VER_CACHE_SECONDS"
ENV_CATALOGUE_TIMEOUT_SECONDS = "PERMISSION_CATALOGUE_TIMEOUT_SECONDS"


class InvalidBitset(ValueError):
    pass


# ─── Bitset (mirror of Core's app/core/permission_index.unpack_indexes) ───────

def unpack_indexes(b64: str) -> set[int]:
    """base64url (no padding) bitset -> set of indexes. Byte-for-byte the inverse of Core's pack_indexes."""
    if not b64:
        return set()
    try:
        raw = base64.urlsafe_b64decode(b64 + "=" * (-len(b64) % 4))
    except (ValueError, TypeError, binascii.Error) as exc:
        raise InvalidBitset(f"not base64url: {exc}") from exc
    out: set[int] = set()
    for byte_no, byte in enumerate(raw):
        while byte:
            low = byte & -byte
            out.add(byte_no * 8 + low.bit_length() - 1)
            byte ^= low
    return out


# ─── Catalogue ────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class Catalogue:
    version: int
    idx_by_code: dict[str, int]
    known_idx: frozenset[int]

    @classmethod
    def parse(cls, body: Any) -> Catalogue:
        """Core's AuthzCatalogueResponse (full list, no since_version). Raises ValueError on anything else."""
        if not isinstance(body, dict):
            raise ValueError("catalogue body is not an object")
        version = body.get("version")
        entries = body.get("entries")
        if not isinstance(version, int) or isinstance(version, bool) or version < 1:
            raise ValueError("catalogue version missing or < 1")
        if not isinstance(entries, list):
            raise ValueError("catalogue entries missing")
        idx_by_code: dict[str, int] = {}
        for e in entries:
            if not isinstance(e, dict):
                raise ValueError("catalogue entry is not an object")
            idx, code = e.get("idx"), e.get("code")
            if not isinstance(idx, int) or isinstance(idx, bool) or idx < 0 or not isinstance(code, str) or not code:
                raise ValueError("catalogue entry malformed")
            if code in idx_by_code:
                raise ValueError(f"duplicate code {code!r}")
            idx_by_code[code] = idx
        known = frozenset(idx_by_code.values())
        if len(known) != len(idx_by_code):
            raise ValueError("duplicate idx")
        return cls(version=version, idx_by_code=idx_by_code, known_idx=known)


class _CatalogueUnavailable(Exception):
    pass


# ─── Result ───────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class LocalDecision:
    """granted is True/False when the token answered; None with a `reason` when the caller must ask Core."""

    granted: bool | None
    reason: str | None = None
    catalogue_version: int | None = None
    token_authz_ver: int | None = None
    current_authz_ver: int | None = None

    @property
    def usable(self) -> bool:
        return self.granted is not None


def _fallback(reason: str, **kw: Any) -> LocalDecision:
    return LocalDecision(granted=None, reason=reason, **kw)


# ─── Evaluator ────────────────────────────────────────────────────────────────

class LocalEvaluator:
    """Catalogue snapshot + authz_ver cache for one process. Built by configure_permissions() when local_mode != off."""

    def __init__(
        self,
        *,
        core_url: str,
        timeout_seconds: float,
        transport: httpx.AsyncBaseTransport | None,
        clock: Callable[[], float],
        redis: Any = None,
        redis_url: str | None = None,
        authz_ver_cache_seconds: float = DEFAULT_AUTHZ_VER_CACHE_SECONDS,
        redis_timeout_seconds: float = DEFAULT_REDIS_TIMEOUT_SECONDS,
        catalogue_retry_seconds: float = DEFAULT_CATALOGUE_RETRY_SECONDS,
        catalogue_timeout_seconds: float | None = None,
    ) -> None:
        self._core_url = core_url.rstrip("/")
        # The catalogue fetch is the only HTTP call this evaluator makes. `timeout_seconds` (the permission-check timeout)
        # is kept only as the fallback for a caller that builds an evaluator directly without a catalogue timeout.
        self._timeout = catalogue_timeout_seconds if catalogue_timeout_seconds is not None else timeout_seconds
        self._transport = transport
        self._clock = clock
        self._client: httpx.AsyncClient | None = None
        # Redis: an explicit client (tests), else a URL (connected lazily), else the session-revocation client.
        self._redis = redis
        self._redis_url = redis_url
        self._owns_redis = False
        self._ver_ttl = min(max(0.0, authz_ver_cache_seconds), MAX_AUTHZ_VER_CACHE_SECONDS)
        self._redis_timeout = redis_timeout_seconds
        # (expires_at, value or None, failure reason or None)
        self._ver_cached: tuple[float, int | None, str | None] | None = None
        self._ver_task: asyncio.Task[tuple[int | None, str | None]] | None = None
        self._catalogue: Catalogue | None = None
        self._cat_task: asyncio.Task[None] | None = None
        self._cat_blocked_until = float("-inf")
        self._cat_retry = catalogue_retry_seconds

    # ── public ────────────────────────────────────────────────────────────────

    async def evaluate(self, ctx: AuthContext, token: str, code: str) -> LocalDecision:
        """The token's answer for `code`, or a fallback reason. Never raises (an unexpected error is reason "error")."""
        try:
            return await self._evaluate(ctx, token, code)
        except Exception:
            _log.exception("permission_local_error")
            return _fallback("error")

    async def aclose(self) -> None:
        task = self._cat_task
        if task is not None and not task.done():
            task.cancel()
        self._cat_task = None
        if self._client is not None:
            await self._client.aclose()
            self._client = None
        if self._owns_redis and self._redis is not None:
            with contextlib.suppress(Exception):
                await self._redis.aclose()
            self._redis = None
            self._owns_redis = False

    # ── steps ─────────────────────────────────────────────────────────────────

    async def _evaluate(self, ctx: AuthContext, token: str, code: str) -> LocalDecision:
        try:
            claims = jwt.get_unverified_claims(token)  # verified moments ago by require_tenant(); re-read, not re-trusted
        except JWTError:
            return _fallback("service_token" if ctx.is_service else "token_unreadable")
        if ctx.is_service:
            # 0.6.4 (G8): a SCOPED service token (Core SERVICE_TOKEN_SCOPES=enforce: ver=2 + perm = role INTERSECT the
            # account's scopes) is evaluated exactly like a staff v2 token. An unscoped one keeps asking Core.
            if claims.get("ver") != 2 or claims.get("type") != "service" or "perm" not in claims:
                return _fallback("service_token")
        elif claims.get("ver") != 2 or claims.get("type") != "access":
            return _fallback("v1_token")
        if str(claims.get("sub")) != str(ctx.user_id) or str(claims.get("tid")) != str(ctx.tenant_id):
            return _fallback("token_unreadable")

        perm = claims.get("perm")
        if not isinstance(perm, dict):
            return _fallback("no_perm")
        cv, bits = perm.get("cv"), perm.get("b")
        if not isinstance(cv, int) or isinstance(cv, bool) or cv < 1 or not isinstance(bits, str):
            return _fallback("no_perm")

        # Before anything else can fall back: make sure a catalogue at >= cv is (being) loaded. Never awaited.
        self._preload(cv, token, ctx)

        token_ver = claims.get("authz_ver")
        if not isinstance(token_ver, int) or isinstance(token_ver, bool):
            return _fallback("no_authz_ver", catalogue_version=cv)

        current, why = await self._current_authz_ver()
        if why is not None:
            return _fallback(why, catalogue_version=cv, token_authz_ver=token_ver)
        if current != token_ver:
            return _fallback("authz_ver_stale", catalogue_version=cv, token_authz_ver=token_ver, current_authz_ver=current)
        fresh = {"catalogue_version": cv, "token_authz_ver": token_ver, "current_authz_ver": current}

        catalogue = self._catalogue
        if catalogue is None:
            return _fallback("catalogue_loading" if self._cat_task is not None else "catalogue_unavailable", **fresh)
        if catalogue.version < cv:
            return _fallback("catalogue_behind", **fresh)

        try:
            held = unpack_indexes(bits)
        except InvalidBitset:
            return _fallback("invalid_bitset", **fresh)
        if not held <= catalogue.known_idx:
            return _fallback("invalid_bitset", **fresh)

        idx = catalogue.idx_by_code.get(code)
        if idx is None:
            return _fallback("unknown_code", **fresh)
        return LocalDecision(granted=idx in held, **fresh)

    # ── freshness ─────────────────────────────────────────────────────────────

    def _redis_client(self) -> Any:
        if self._redis is not None:
            return self._redis
        if self._redis_url:
            import redis.asyncio as aioredis  # noqa: PLC0415 -- optional dependency, as in session_revocation

            self._redis = aioredis.Redis.from_url(
                self._redis_url, decode_responses=True,
                socket_connect_timeout=self._redis_timeout, socket_timeout=self._redis_timeout,
                health_check_interval=30,
            )
            self._owns_redis = True
            return self._redis
        # Reuse the session-revocation client when the service configured one (it points at Core's Redis today).
        from blumax_auth import session_revocation  # noqa: PLC0415

        checker = session_revocation._checker
        return getattr(checker, "redis", None) if checker is not None else None

    async def _current_authz_ver(self) -> tuple[int | None, str | None]:
        """(current authz_ver, None) or (None, fallback reason). Cached for authz_ver_cache_seconds, failures too."""
        now = self._clock()
        cached = self._ver_cached
        if cached is not None and now < cached[0]:
            return cached[1], cached[2]
        task = self._ver_task
        if task is None:
            task = asyncio.ensure_future(self._read_authz_ver())
            self._ver_task = task
            task.add_done_callback(self._ver_settled)
        value, why = await asyncio.shield(task)
        return value, why

    def _ver_settled(self, task: asyncio.Task[tuple[int | None, str | None]]) -> None:
        if self._ver_task is task:
            self._ver_task = None
        if not task.cancelled() and task.exception() is None:
            value, why = task.result()
            self._ver_cached = (self._clock() + self._ver_ttl, value, why)

    async def _read_authz_ver(self) -> tuple[int | None, str | None]:
        client = self._redis_client()
        if client is None:
            return None, "authz_ver_not_configured"
        try:
            raw = await asyncio.wait_for(client.get(AUTHZ_VER_KEY), self._redis_timeout)
        except Exception as exc:  # noqa: BLE001 -- includes ACL NOPERM, timeouts, connection errors
            _log.warning("permission_local_authz_ver_unavailable error=%s", type(exc).__name__, extra={"error": type(exc).__name__})
            return None, "authz_ver_unavailable"
        if raw is None:
            return None, "authz_ver_unset"
        try:
            return int(raw.decode() if isinstance(raw, bytes) else raw), None
        except (TypeError, ValueError):
            return None, "authz_ver_unavailable"

    # ── catalogue ─────────────────────────────────────────────────────────────

    def _http(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                base_url=self._core_url, timeout=self._timeout, transport=self._transport,
                limits=httpx.Limits(keepalive_expiry=3.0),
            )
        return self._client

    def _preload(self, cv: int, token: str, ctx: AuthContext) -> None:
        """Start ONE background fetch when no catalogue at >= `cv` is held, none is in flight and no back-off applies.

        Never awaited by a request: the caller falls back (catalogue_loading / catalogue_behind) until it has landed.
        """
        held = self._catalogue
        if held is not None and held.version >= cv:
            return
        task = self._cat_task
        if task is not None:
            if not task.done() and task.get_loop() is asyncio.get_running_loop():
                return  # already loading
            self._cat_task = None  # left behind by a closed event loop (tests): start afresh
        if self._clock() < self._cat_blocked_until:
            return
        task = asyncio.ensure_future(self._load(cv, token, ctx))
        self._cat_task = task
        task.add_done_callback(self._cat_settled)

    async def _load(self, cv: int, token: str, ctx: AuthContext) -> None:
        try:
            fetched = await self._fetch_catalogue(token, ctx)
        except _CatalogueUnavailable:
            return  # logged and backed off in _catalogue_failed
        except Exception as exc:  # noqa: BLE001 -- a background task: anything unexpected is logged, never raised
            self._catalogue_failed(reason=f"error {type(exc).__name__}", back_off=True)
            return
        if fetched.version < cv:
            self._cat_blocked_until = max(self._cat_blocked_until, self._clock() + CATALOGUE_BEHIND_RETRY_SECONDS)

    def _cat_settled(self, task: asyncio.Task[None]) -> None:
        if self._cat_task is task:
            self._cat_task = None
        if not task.cancelled():
            task.exception()  # mark retrieved

    async def _fetch_catalogue(self, token: str, ctx: AuthContext) -> Catalogue:
        headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
        if ctx.tenant_id is not None:
            headers["X-Tenant-ID"] = str(ctx.tenant_id)
        try:
            resp = await self._http().get(CATALOGUE_PATH, headers=headers)
        except httpx.HTTPError as exc:
            self._catalogue_failed(reason=type(exc).__name__, back_off=True)
            raise _CatalogueUnavailable() from exc
        if resp.status_code != 200:
            # 401/403: THIS caller's token was refused -- not Core being down, so no back-off for everyone else.
            self._catalogue_failed(reason=f"status_{resp.status_code}", back_off=resp.status_code >= 500)
            raise _CatalogueUnavailable()
        try:
            catalogue = Catalogue.parse(resp.json())
        except ValueError as exc:
            self._catalogue_failed(reason=f"malformed: {exc}", back_off=True)
            raise _CatalogueUnavailable() from exc
        held = self._catalogue
        if held is None or catalogue.version >= held.version:
            self._catalogue = catalogue
            _log.info(
                "permission_catalogue_loaded catalogue_version=%s codes=%s", catalogue.version, len(catalogue.idx_by_code),
                extra={"catalogue_version": catalogue.version, "codes": len(catalogue.idx_by_code)},
            )
        return self._catalogue  # type: ignore[return-value]

    def _catalogue_failed(self, *, reason: str, back_off: bool) -> None:
        retry_in = self._cat_retry if back_off else 0.0
        _log.warning(
            "permission_catalogue_fetch_failed reason=%s back_off=%s retry_in_s=%s timeout_s=%s",
            reason, back_off, retry_in, self._timeout,
            extra={"reason": reason, "back_off": back_off, "timeout_seconds": self._timeout},
        )
        if back_off:
            self._cat_blocked_until = self._clock() + self._cat_retry


def env_cache_seconds() -> float | None:
    raw = os.environ.get(ENV_CACHE_SECONDS, "").strip()
    if not raw:
        return None
    try:
        return float(raw)
    except ValueError:
        return None


def env_catalogue_timeout_seconds() -> float | None:
    """PERMISSION_CATALOGUE_TIMEOUT_SECONDS, or None when unset. An unparsable value is ignored (with a warning)."""
    raw = os.environ.get(ENV_CATALOGUE_TIMEOUT_SECONDS, "").strip()
    if not raw:
        return None
    try:
        return float(raw)
    except ValueError:
        _log.warning("permission_catalogue_timeout_invalid value=%r", raw, extra={"value": raw})
        return None
