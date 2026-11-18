"""APP-005 (JWKS stale serving, no refresh storm), APP-006 (keep-alive) and APP-007 (circuit breaker on the permission client)."""
from __future__ import annotations

import asyncio
import time
import types
import uuid

import httpx
import pytest
from test_permissions import CORE, FakeClock, FakeCore

import blumax_auth.jwks as jwks_module
from blumax_auth.errors import InvalidToken
from blumax_auth.jwks import JwksCache
from blumax_auth.permissions import PermissionCheckUnavailable, _Checker


# ─── JWKS ───────────────────────────────────────────────────────────────────

def jwk(kid: str) -> dict:
    return {"kid": kid, "kty": "RSA", "n": "x", "e": "AQAB"}


class FakeJwksHttp:
    """Replaces httpx.AsyncClient inside the jwks module; scripted per test."""

    def __init__(self):
        self.calls = 0
        self.delay = 0.0
        self.fail: Exception | None = None
        self.body: dict = {"keys": []}

    def client_factory(self):
        outer = self

        class _Client:
            def __init__(self, *a, **k):
                pass

            async def __aenter__(self):
                return self

            async def __aexit__(self, *exc):
                return False

            async def get(self, url):
                outer.calls += 1
                if outer.delay:
                    await asyncio.sleep(outer.delay)
                if outer.fail is not None:
                    raise outer.fail
                return types.SimpleNamespace(raise_for_status=lambda: None, json=lambda: outer.body)

        return _Client


@pytest.fixture()
def world(monkeypatch):
    clock = FakeClock()
    http = FakeJwksHttp()
    # A private time shim for the jwks module only: patching time.monotonic itself would freeze asyncio's own timers.
    monkeypatch.setattr(jwks_module, "time", types.SimpleNamespace(monotonic=clock))
    monkeypatch.setattr(jwks_module.httpx, "AsyncClient", http.client_factory())
    cache = JwksCache("http://core.test/jwks.json", ttl_seconds=3600, min_refetch_interval=10.0, max_stale_seconds=86400)
    cache.seed({"keys": [jwk("k1")]})
    return cache, http, clock


async def test_expired_ttl_with_core_down_serves_the_held_key_at_once_with_one_attempt(world):
    cache, http, clock = world
    clock.advance(4000)  # past the 1 h TTL, well inside the 24 h stale bound
    http.fail = httpx.ConnectTimeout("core down")
    http.delay = 0.3
    started = time.perf_counter()
    results = await asyncio.gather(*[cache.get_key("k1") for _ in range(30)])
    elapsed = time.perf_counter() - started
    assert all(r["kid"] == "k1" for r in results)
    assert http.calls == 1  # single flight: one attempt, not one per request
    assert elapsed < 1.0  # the old code queued 30 x the fetch time behind the lock


async def test_after_a_failed_attempt_no_new_attempt_until_the_floor_passes(world):
    cache, http, clock = world
    clock.advance(4000)
    http.fail = httpx.ConnectError("down")
    await cache.get_key("k1")
    assert http.calls == 1
    for _ in range(5):
        await cache.get_key("k1")
    assert http.calls == 1  # inside the back-off
    clock.advance(11)
    await cache.get_key("k1")
    assert http.calls == 2


async def test_recovery_refreshes_and_clears_the_back_off(world):
    cache, http, clock = world
    clock.advance(4000)
    http.fail = httpx.ConnectError("down")
    await cache.get_key("k1")
    clock.advance(11)
    http.fail = None
    http.body = {"keys": [jwk("k1"), jwk("k2")]}
    assert (await cache.get_key("k1"))["kid"] == "k1"
    assert (await cache.get_key("k2"))["kid"] == "k2"  # the new key set was installed
    calls = http.calls
    await cache.get_key("k1")
    assert http.calls == calls  # fresh again: no more fetching


async def test_the_stale_bound_still_fails_closed(world):
    cache, http, clock = world
    clock.advance(86400 + 10)  # older than the hard bound
    http.fail = httpx.ConnectError("down")
    with pytest.raises(InvalidToken):
        await cache.get_key("k1")


async def test_a_withdrawn_key_is_refused_after_a_successful_refresh(world):
    cache, http, clock = world
    clock.advance(4000)
    http.body = {"keys": [jwk("k2")]}  # Core rotated k1 out
    with pytest.raises(InvalidToken):
        await cache.get_key("k1")
    assert (await cache.get_key("k2"))["kid"] == "k2"


async def test_an_empty_key_set_is_a_failed_refresh_and_keeps_the_held_keys(world):
    cache, http, clock = world
    clock.advance(4000)
    http.body = {"keys": []}
    assert (await cache.get_key("k1"))["kid"] == "k1"
    for _ in range(4):
        await cache.get_key("k1")
    assert http.calls == 1  # backed off, not re-fetched on every request


async def test_cold_cache_with_core_down_fails_fast_after_the_first_attempt(monkeypatch):
    clock = FakeClock()
    http = FakeJwksHttp()
    # A private time shim for the jwks module only: patching time.monotonic itself would freeze asyncio's own timers.
    monkeypatch.setattr(jwks_module, "time", types.SimpleNamespace(monotonic=clock))
    monkeypatch.setattr(jwks_module.httpx, "AsyncClient", http.client_factory())
    cache = JwksCache("http://core.test/jwks.json", min_refetch_interval=10.0)
    http.fail = httpx.ConnectError("down")
    for _ in range(6):
        with pytest.raises(InvalidToken):
            await cache.get_key("k1")
    assert http.calls == 1  # the later requests did not each wait out a fetch


# ─── permission client: breaker + keep-alive ────────────────────────────────

class Rig:
    def __init__(self, failures=3, open_seconds=10.0):
        self.core = FakeCore()
        self.clock = FakeClock()
        self.checker = _Checker(
            core_url=CORE, ttl_seconds=30.0, timeout_seconds=2.0, max_entries=100,
            transport=httpx.MockTransport(self.core.handle), clock=self.clock,
            breaker_failures=failures, breaker_open_seconds=open_seconds,
        )
        self.tenant = uuid.uuid4()
        self._n = 0

    async def ask(self, token=None):
        self._n += 1
        token = token or f"tok-{self._n}"  # distinct callers: each is its own cache key
        ctx = types.SimpleNamespace(tenant_id=self.tenant, user_id=uuid.uuid4())
        return await self.checker.granted(ctx, token)


async def test_breaker_opens_after_n_failures_then_refuses_without_calling_core():
    r = Rig(failures=3)
    r.core.fail = httpx.ConnectError("core down")
    for _ in range(3):
        with pytest.raises(PermissionCheckUnavailable):
            await r.ask()
    assert r.core.calls == 3
    for _ in range(10):
        with pytest.raises(PermissionCheckUnavailable):  # still the same fail-closed 503, never a grant
            await r.ask()
    assert r.core.calls == 3  # Core was not asked


async def test_breaker_probes_after_the_open_period_and_closes_on_success():
    r = Rig(failures=2, open_seconds=10.0)
    r.core.fail = httpx.ReadTimeout("slow")
    for _ in range(2):
        with pytest.raises(PermissionCheckUnavailable):
            await r.ask()
    r.clock.advance(11)
    r.core.fail = None
    r.core.grant("probe", "a.b.c")
    answer = await r.ask("probe")
    assert answer.codes == frozenset({"a.b.c"})
    calls = r.core.calls
    r.core.grant("next", "x.y.z")
    await r.ask("next")
    assert r.core.calls == calls + 1  # closed: asking normally


async def test_a_failed_probe_reopens_the_breaker_at_once():
    r = Rig(failures=2, open_seconds=10.0)
    r.core.fail = httpx.ConnectError("down")
    for _ in range(2):
        with pytest.raises(PermissionCheckUnavailable):
            await r.ask()
    r.clock.advance(11)
    with pytest.raises(PermissionCheckUnavailable):
        await r.ask()  # the probe fails
    calls = r.core.calls
    with pytest.raises(PermissionCheckUnavailable):
        await r.ask()
    assert r.core.calls == calls  # open again


async def test_core_answering_403_or_401_is_not_an_outage():
    r = Rig(failures=2)
    for i in range(6):
        r.core.respond(f"t{i}", 403 if i % 2 else 401)
    for i in range(6):
        with pytest.raises(Exception) as exc:
            await r.ask(f"t{i}")
        assert not isinstance(exc.value, PermissionCheckUnavailable)
    r.core.grant("ok", "a.b.c")
    assert (await r.ask("ok")).codes == frozenset({"a.b.c"})  # breaker never opened


async def test_5xx_and_malformed_answers_count_as_outage():
    r = Rig(failures=3)
    r.core.respond("a", 503)
    r.core.respond("b", 200, {"nope": 1})
    r.core.respond("c", 500)
    for t in ("a", "b", "c"):
        with pytest.raises(PermissionCheckUnavailable):
            await r.ask(t)
    assert r.checker._breaker_is_open()


async def test_a_success_resets_the_failure_count():
    r = Rig(failures=3)
    r.core.fail = httpx.ConnectError("down")
    for _ in range(2):
        with pytest.raises(PermissionCheckUnavailable):
            await r.ask()
    r.core.fail = None
    r.core.grant("ok", "a.b.c")
    await r.ask("ok")
    r.core.fail = httpx.ConnectError("down")
    for _ in range(2):
        with pytest.raises(PermissionCheckUnavailable):
            await r.ask()
    assert not r.checker._breaker_is_open()  # only 2 since the success


async def test_breaker_off_when_zero():
    r = Rig(failures=0)
    r.core.fail = httpx.ConnectError("down")
    for _ in range(12):
        with pytest.raises(PermissionCheckUnavailable):
            await r.ask()
    assert r.core.calls == 12


async def test_breaker_never_serves_a_cached_grant_beyond_its_ttl():
    """An open breaker is fail-closed: after the cached answer expires the caller is refused, not allowed."""
    r = Rig(failures=1, open_seconds=60.0)
    r.core.grant("alice", "a.b.c")
    assert (await r.ask("alice")).codes == frozenset({"a.b.c"})
    r.clock.advance(31)  # past the 30 s TTL
    r.core.fail = httpx.ConnectError("down")
    with pytest.raises(PermissionCheckUnavailable):
        await r.ask("alice")


def test_http_client_keepalive_expires_before_uvicorns_five_seconds():
    checker = _Checker(core_url=CORE, ttl_seconds=30.0, timeout_seconds=2.0, max_entries=10, transport=None, clock=time.monotonic)
    client = checker._http()
    assert client._transport._pool._keepalive_expiry == 3.0
    asyncio.run(client.aclose())
