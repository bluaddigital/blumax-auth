# ruff: noqa: F811 -- pytest fixtures imported from test_local_permissions
"""0.6.3: scoped authz versions (Core AUTHZ_VER_SCOPE=scoped) -- authz_tv / authz_uv checked with ONE MGET.

A token without the new claims keeps exactly the 0.6.1 global-only check (covered by test_local_permissions.py, which
runs unchanged); here: match / mismatch per level, absent tenant/user key, one MGET per (tenant, user) per window, the
cache bound, malformed claims and Redis trouble -> always a fallback (Core decides), never a local grant on doubt.
"""
from __future__ import annotations

import asyncio
import logging
import uuid

import pytest
from test_local_permissions import (  # noqa: F401 -- fixtures re-used by name
    HELD,
    LOGGER,
    PERMS,
    FakeClock,
    _clean,
    bearer,
    client,
    clock,
    configure,
    core,
    mint,
    settle,
    shadow_records,
    signer,
)

import blumax_auth
from blumax_auth import metrics
from blumax_auth.local_permissions import MAX_SCOPED_CACHE_ENTRIES

TID = str(uuid.uuid4())
SUB = str(uuid.uuid4())
G, T, U = "authctx:authz_ver", f"authctx:authz_ver:t:{TID}", f"authctx:authz_ver:u:{TID}:{SUB}"


class ScopedRedis:
    def __init__(self) -> None:
        self.values: dict[str, object] = {G: "7", T: "19a2b3c4d5e6f.0a1b2c3d", U: "19a2b3c4d5e70.ffeeddcc"}
        self.mgets: list[list[str]] = []
        self.gets = 0
        self.fail: Exception | None = None

    async def get(self, key: str) -> object:
        self.gets += 1
        if self.fail is not None:
            raise self.fail
        return self.values.get(key)

    async def mget(self, keys: list[str]) -> list[object]:
        self.mgets.append(list(keys))
        if self.fail is not None:
            raise self.fail
        return [self.values.get(k) for k in keys]


@pytest.fixture
def redis() -> ScopedRedis:
    return ScopedRedis()


def scoped(signer, redis: ScopedRedis, *, tid: str = TID, sub: str = SUB, **over) -> str:
    tv = over.pop("authz_tv", redis.values.get(f"authctx:authz_ver:t:{tid}") or "t-init")
    uv = over.pop("authz_uv", redis.values.get(f"authctx:authz_ver:u:{tid}:{sub}") or "u-init")
    return mint(signer, tid=tid, sub=sub, authz_tv=tv, authz_uv=uv, **over)


class TestScopedLocal:
    @pytest.fixture(autouse=True)
    def _local(self, core, clock, redis):
        configure(core, clock, redis, local_mode="local")

    async def _warm(self, client, signer, redis, core):
        """First request loads the catalogue (asks Core); afterwards local decisions are possible."""
        t = scoped(signer, redis)
        core.grant(t, HELD)
        await client.get("/held", headers=bearer(t))
        await settle()
        metrics.reset_metrics()

    async def test_all_three_match_decides_locally_with_one_mget(self, client, signer, core, redis):
        await self._warm(client, signer, redis, core)
        asked = core.calls(PERMS)
        token = scoped(signer, redis, codes=(HELD,))
        assert (await client.get("/held", headers=bearer(token))).status_code == 200
        assert (await client.get("/not-held", headers=bearer(token))).status_code == 403
        assert metrics.local_snapshot() == {"local_allow": 1, "local_deny": 1}
        assert redis.mgets == [[G, T, U]] and redis.gets == 0   # one MGET for all three, cached for the window
        assert core.calls(PERMS) == asked                        # Core was not asked

    @pytest.mark.parametrize(("key", "scope"), [(G, "global"), (T, "tenant"), (U, "user")])
    async def test_mismatch_at_each_level_asks_core(self, client, signer, core, clock, redis, caplog, key, scope):
        await self._warm(client, signer, redis, core)
        token = scoped(signer, redis, codes=(HELD,))   # the token says yes ...
        core.grant(token)                               # ... Core (after the change) says no
        redis.values[key] = "8" if key == G else "19a2b3c4d5fff.12345678"
        clock.advance(2.1)
        with caplog.at_level(logging.INFO, logger=LOGGER):
            assert (await client.get("/held", headers=bearer(token))).status_code == 403
        assert metrics.local_snapshot() == {"fallback:authz_ver_stale": 1}
        [rec] = shadow_records(caplog, "permission_local_fallback")
        assert rec.authz_stale_scope == scope and f"authz_stale_scope={scope}" in rec.getMessage()

    @pytest.mark.parametrize("key", [T, U])
    async def test_absent_tenant_or_user_key_never_matches(self, client, signer, core, clock, redis, key):
        """Core creates both keys before minting; absent = evicted / flushed -> stale, never "never changed"."""
        await self._warm(client, signer, redis, core)
        token = scoped(signer, redis, codes=(HELD,))
        core.grant(token)
        del redis.values[key]
        clock.advance(2.1)
        assert (await client.get("/held", headers=bearer(token))).status_code == 403
        assert metrics.local_snapshot() == {"fallback:authz_ver_stale": 1}

    async def test_global_key_absent_is_unset(self, client, signer, core, clock, redis):
        await self._warm(client, signer, redis, core)
        token = scoped(signer, redis)
        core.grant(token, HELD)
        del redis.values[G]
        clock.advance(2.1)
        assert (await client.get("/held", headers=bearer(token))).status_code == 200
        assert metrics.local_snapshot() == {"fallback:authz_ver_unset": 1}

    @pytest.mark.parametrize("over", [
        {"authz_tv": None}, {"authz_uv": None}, {"authz_tv": 5}, {"authz_uv": ""},
    ])
    async def test_malformed_scoped_claims_fall_back(self, client, signer, core, redis, over):
        await self._warm(client, signer, redis, core)
        token = scoped(signer, redis, codes=(HELD,), **over)
        core.grant(token)
        assert (await client.get("/held", headers=bearer(token))).status_code == 403
        assert metrics.local_snapshot() == {"fallback:no_authz_ver": 1}

    async def test_redis_down_falls_back(self, client, signer, core, clock, redis):
        await self._warm(client, signer, redis, core)
        redis.fail = ConnectionError("down")
        clock.advance(2.1)
        token = scoped(signer, redis, codes=(HELD,))
        core.grant(token)
        assert (await client.get("/held", headers=bearer(token))).status_code == 403
        assert metrics.local_snapshot() == {"fallback:authz_ver_unavailable": 1}

    async def test_short_mget_reply_falls_back(self, client, signer, core, clock, redis):
        await self._warm(client, signer, redis, core)

        async def short(keys):
            return ["7"]
        redis.mget = short  # type: ignore[method-assign]
        clock.advance(2.1)
        token = scoped(signer, redis, codes=(HELD,))
        core.grant(token)
        assert (await client.get("/held", headers=bearer(token))).status_code == 403
        assert metrics.local_snapshot() == {"fallback:authz_ver_unavailable": 1}

    async def test_another_users_change_does_not_touch_this_user(self, client, signer, core, clock, redis):
        await self._warm(client, signer, redis, core)
        redis.values[f"authctx:authz_ver:u:{TID}:{uuid.uuid4()}"] = "someone-else"
        redis.values[f"authctx:authz_ver:t:{uuid.uuid4()}"] = "another-tenant"
        clock.advance(2.1)
        token = scoped(signer, redis, codes=(HELD,))
        assert (await client.get("/held", headers=bearer(token))).status_code == 200
        assert metrics.local_snapshot() == {"local_allow": 1}

    async def test_cache_per_caller_and_window(self, client, signer, core, clock, redis):
        await self._warm(client, signer, redis, core)
        other = str(uuid.uuid4())
        redis.values[f"authctx:authz_ver:u:{TID}:{other}"] = "o1"
        for _ in range(3):
            await client.get("/held", headers=bearer(scoped(signer, redis, codes=(HELD,))))
            await client.get("/held", headers=bearer(scoped(signer, redis, sub=other, codes=(HELD,))))
        assert len(redis.mgets) == 2   # one per (tenant, user), not per request
        clock.advance(2.1)
        await client.get("/held", headers=bearer(scoped(signer, redis, codes=(HELD,))))
        assert len(redis.mgets) == 3

    async def test_old_token_without_scoped_claims_uses_the_global_get(self, client, signer, core, redis):
        await self._warm(client, signer, redis, core)
        n = len(redis.mgets)
        token = mint(signer, tid=TID, sub=SUB, codes=(HELD,))
        assert (await client.get("/held", headers=bearer(token))).status_code == 200
        assert redis.gets == 1 and len(redis.mgets) == n


async def test_concurrent_misses_share_one_mget(core, clock):
    redis = ScopedRedis()
    gate = asyncio.Event()
    real = redis.mget

    async def slow(keys):
        await gate.wait()
        return await real(keys)
    redis.mget = slow  # type: ignore[method-assign]
    configure(core, clock, redis, local_mode="shadow")
    local = blumax_auth.permissions._checker.local
    tasks = [asyncio.ensure_future(local._current_scoped(TID, SUB)) for _ in range(5)]
    await asyncio.sleep(0)
    gate.set()
    results = await asyncio.gather(*tasks)
    assert len(redis.mgets) == 1 and len({r for r in results}) == 1


async def test_scoped_cache_is_bounded(core):
    clock = FakeClock()
    redis = ScopedRedis()
    configure(core, clock, redis, local_mode="shadow")
    local = blumax_auth.permissions._checker.local
    assert local._scoped_max == MAX_SCOPED_CACHE_ENTRIES
    local._scoped_max = 3
    users = [str(uuid.uuid4()) for _ in range(5)]
    for u in users:
        await local._current_scoped(TID, u)
    await asyncio.sleep(0)
    assert len(local._scoped_cached) == 3
    assert list(local._scoped_cached) == [(TID, u) for u in users[2:]]   # oldest evicted first
