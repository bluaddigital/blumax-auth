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
"""
from __future__ import annotations

import asyncio
import time
from typing import Any

import httpx

from blumax_auth.errors import InvalidToken


class JwksCache:
    """Caches Core's public keys, refetching on TTL expiry or an unknown kid."""

    def __init__(
        self,
        jwks_url: str,
        *,
        ttl_seconds: float = 3600.0,
        timeout_seconds: float = 5.0,
        min_refetch_interval: float = 10.0,
    ) -> None:
        self._url = jwks_url
        self._ttl = ttl_seconds
        self._timeout = timeout_seconds
        # Floor between unknown-kid refetches. Without it, a stream of tokens
        # carrying random kids becomes a request amplifier pointed at Core.
        self._min_refetch_interval = min_refetch_interval

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
        if (key := self._match(kid)) is not None:
            return key

        # Unknown kid against a fresh cache: either a rotation we have not seen
        # yet, or a forged header. One more fetch distinguishes them.
        if time.monotonic() - self._last_attempt >= self._min_refetch_interval:
            await self._refresh(force=True)
            if (key := self._match(kid)) is not None:
                return key

        raise InvalidToken("Token signed with an unrecognised key")

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
        return bool(self._keys) and (time.monotonic() - self._fetched_at) < self._ttl

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
