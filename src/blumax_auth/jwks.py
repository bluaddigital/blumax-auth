"""JWKS fetch and cache.

The only network call this package makes, and it is off the request path
whenever the cache is warm. Verification itself is CPU-only, so a service that
has fetched the key set once keeps authenticating requests even while Core is
unreachable — which is the failure-isolation property that made claim-based
authorization worth choosing over calling Core per request.

Rotation
--------
Core publishes the current key and, during a rotation, the retiring one. A
token whose `kid` is not in the cache triggers exactly one refetch (rate-limited
so an attacker cannot turn unknown kids into a request amplifier against Core).
That is what lets Core rotate without every service restarting in lockstep.

Maximum stale age
-----------------
While Core is unreachable the cache keeps serving the keys it holds, so a Core
outage does not stop authentication. That grace is bounded: once the keys are
older than `max_stale_seconds` (default 24h; env BLUMAX_AUTH_JWKS_MAX_STALE_SECONDS
when the argument is not given; 0 disables the bound) and a refresh still
fails, verification fails closed. Otherwise a key Core has withdrawn (e.g. a
compromised key rotated out) would be trusted indefinitely by a service that
cannot reach Core.
"""
from __future__ import annotations

import asyncio
import os
import time
from typing import Any

import httpx

from blumax_auth.errors import InvalidToken

DEFAULT_MAX_STALE_SECONDS = 24 * 3600.0


class JwksCache:
    """Caches Core's public keys, refetching on TTL expiry or an unknown kid."""

    def __init__(
        self,
        jwks_url: str,
        *,
        ttl_seconds: float = 3600.0,
        timeout_seconds: float = 5.0,
        min_refetch_interval: float = 10.0,
        max_stale_seconds: float | None = None,
    ) -> None:
        self._url = jwks_url
        self._ttl = ttl_seconds
        self._timeout = timeout_seconds
        # Floor between unknown-kid refetches. Without it, a stream of tokens
        # carrying random kids becomes a request amplifier pointed at Core.
        self._min_refetch_interval = min_refetch_interval

        if max_stale_seconds is None:
            raw = os.environ.get("BLUMAX_AUTH_JWKS_MAX_STALE_SECONDS", "").strip()
            try:
                max_stale_seconds = float(raw) if raw else DEFAULT_MAX_STALE_SECONDS
            except ValueError as exc:
                raise ValueError(
                    "BLUMAX_AUTH_JWKS_MAX_STALE_SECONDS must be a number of seconds"
                ) from exc
        if max_stale_seconds < 0:
            raise ValueError("max_stale_seconds must be >= 0 (0 disables the bound)")
        self._max_stale = max_stale_seconds

        self._keys: dict[str, dict[str, Any]] = {}
        self._fetched_at: float = 0.0
        self._last_attempt: float = 0.0
        self._lock = asyncio.Lock()

    # ── Test / bootstrap seam ────────────────────────────────────────────

    def seed(self, jwks: dict[str, Any]) -> None:
        """Install a key set directly, bypassing the network.

        Used by tests, and by any deployment that ships Core's public keys as
        config rather than discovering them.
        """
        self._install(jwks)

    def clear(self) -> None:
        self._keys = {}
        self._fetched_at = 0.0
        self._last_attempt = 0.0

    # ── Lookup ───────────────────────────────────────────────────────────

    async def get_key(self, kid: str | None) -> dict[str, Any]:
        """Return the JWK for `kid`, refetching once if it is unknown."""
        if self._is_fresh() and (key := self._match(kid)) is not None:
            return key

        await self._refresh(force=False)
        self._enforce_max_stale()
        if (key := self._match(kid)) is not None:
            return key

        # Unknown kid against a fresh cache: either a rotation we have not seen
        # yet, or a forged header. One more fetch distinguishes them.
        if time.monotonic() - self._last_attempt >= self._min_refetch_interval:
            await self._refresh(force=True)
            self._enforce_max_stale()
            if (key := self._match(kid)) is not None:
                return key

        raise InvalidToken("Token signed with an unrecognised key")

    def _enforce_max_stale(self) -> None:
        """Fail closed if the held keys are older than the hard stale bound."""
        if (
            self._max_stale > 0
            and self._keys
            and (time.monotonic() - self._fetched_at) > self._max_stale
        ):
            raise InvalidToken("Cannot verify tokens: signing keys are too stale")

    def _match(self, kid: str | None) -> dict[str, Any] | None:
        if kid:
            return self._keys.get(kid)
        # No kid in the header. Unambiguous only when exactly one key is
        # published; during a rotation there are two and guessing would mean
        # accepting a token we cannot attribute to a key.
        if len(self._keys) == 1:
            return next(iter(self._keys.values()))
        return None

    def _is_fresh(self) -> bool:
        # Never "fresh" past the stale bound, even if it was set below the TTL.
        limit = min(self._ttl, self._max_stale) if self._max_stale > 0 else self._ttl
        return bool(self._keys) and (time.monotonic() - self._fetched_at) < limit

    async def _refresh(self, *, force: bool) -> None:
        async with self._lock:
            # Re-check inside the lock: several concurrent requests hitting a
            # cold cache should produce one fetch, not one each.
            if not force and self._is_fresh():
                return
            self._last_attempt = time.monotonic()
            try:
                async with httpx.AsyncClient(timeout=self._timeout) as client:
                    response = await client.get(self._url)
                    response.raise_for_status()
                    self._install(response.json())
            except Exception as exc:
                # Keep serving the keys we already hold. Core being briefly
                # unreachable must not stop a ward from authenticating; the
                # only tokens affected are those signed with a key we have
                # never seen.
                if not self._keys:
                    raise InvalidToken(
                        "Cannot verify tokens: signing keys unavailable"
                    ) from exc

    def _install(self, jwks: dict[str, Any]) -> None:
        keys = {k["kid"]: k for k in jwks.get("keys", []) if k.get("kid")}
        if keys:
            self._keys = keys
            self._fetched_at = time.monotonic()
