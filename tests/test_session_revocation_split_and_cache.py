"""fail_mode="split" (fail closed for writes/sensitive, bounded stale reads) and the optional status cache.

Redis is an in-memory fake with the real client's `mget`, a failure switch and a read counter. The module clock
(`blumax_auth.session_revocation._clock`) is moved by hand, so no test sleeps for a TTL.
"""
import asyncio
import logging
import uuid
from datetime import UTC, datetime, timedelta
from typing import Annotated

import httpx
import pytest
from fastapi import Depends, FastAPI, Request
from test_verification import AUDIENCE, ISSUER, Signer

import blumax_auth
import blumax_auth.session_revocation as sr
from blumax_auth import metrics

LOGGER = "blumax_auth.session_revocation"


class FakeRedis:
    def __init__(self, delay: float = 0.0) -> None:
        self.store: dict[str, str] = {}
        self.fail = False
        self.reads = 0
        self.delay = delay

    async def mget(self, keys):
        self.reads += 1
        if self.delay:
            await asyncio.sleep(self.delay)
        if self.fail:
            raise ConnectionError("store down")
        return [self.store.get(k) for k in keys]

    def revoke(self, user_id, at: datetime) -> None:
        self.store[f"session_revoked_at:{user_id}"] = at.isoformat()


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    for name in (sr.FAIL_MODE_ENV, sr.STALE_READ_ENV, sr.CACHE_SECONDS_ENV, sr.CACHE_MAX_ENTRIES_ENV):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv(sr.BREAKER_ENV, "0")  # no breaker unless a test asks: every unavailable request asks the store
    metrics.reset_metrics()
    yield
    metrics.reset_metrics()


@pytest.fixture
def clock(monkeypatch) -> Clock:
    c = Clock()
    monkeypatch.setattr(sr, "_clock", c)
    return c


@pytest.fixture
def signer() -> Signer:
    return Signer()


@pytest.fixture
def redis() -> FakeRedis:
    return FakeRedis()


def build_app(signer: Signer, redis: FakeRedis, **checker_kwargs) -> FastAPI:
    blumax_auth.reset()
    blumax_auth.reset_session_revocation()
    blumax_auth.configure(jwks_url="http://unused.invalid/jwks.json", issuer=ISSUER, audience=AUDIENCE)
    blumax_auth.jwks_cache().seed(signer.jwks())
    checker_kwargs.setdefault("mode", "enforce")
    sr._checker = sr._Checker(redis, **checker_kwargs)  # type: ignore[arg-type]

    app = FastAPI()
    blumax_auth.install_error_handler(app)
    Check = Annotated[None, Depends(sr.check_session_revocation)]  # noqa: N806
    Sensitive = Annotated[None, Depends(sr.session_revocation_check(sensitive=True))]  # noqa: N806

    async def mark_sensitive(request: Request) -> None:  # what require_permission(admin=True) does
        request.state.blumax_sensitive_route = True

    @app.api_route("/r", methods=["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"])
    async def r(ctx: blumax_auth.Auth, _: Check) -> dict:
        return {"ok": True}

    @app.get("/export")
    async def export(ctx: blumax_auth.Auth, _: Sensitive) -> dict:
        return {"ok": True}

    @app.get("/admin-marked", dependencies=[Depends(mark_sensitive)])
    async def admin_marked(ctx: blumax_auth.Auth, _: Check) -> dict:
        return {"ok": True}

    return app


@pytest.fixture
def make_client(signer, redis):
    clients: list[httpx.AsyncClient] = []

    def _make(**kw) -> httpx.AsyncClient:
        c = httpx.AsyncClient(transport=httpx.ASGITransport(app=build_app(signer, redis, **kw)), base_url="http://t")
        clients.append(c)
        return c

    yield _make
    blumax_auth.reset_session_revocation()
    blumax_auth.reset()


def auth(signer: Signer, uid=None, **over) -> dict[str, str]:
    return {"Authorization": f"Bearer {signer.token(sub=str(uid or uuid.uuid4()), **over)}"}


# ─── split: writes / sensitive fail closed ────────────────────────────────────

@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE"])
async def test_split_writes_fail_closed_with_503_and_retry_after(make_client, signer, redis, clock, method):
    client = make_client(fail_mode="split")
    h = auth(signer)
    assert (await client.request(method, "/r", headers=h)).status_code == 200  # store healthy
    redis.fail = True
    r = await client.request(method, "/r", headers=h)  # still inside the stale window, but a write
    assert r.status_code == 503
    assert r.headers["retry-after"] == "1"  # breaker disabled in this test -> max(1, ceil(0))
    assert r.json()["error"]["code"] == "SESSION_CHECK_UNAVAILABLE"
    snap = metrics.session_snapshot()
    assert snap["store_unavailable"] == 1 and snap["rejected_unavailable"] == 1


async def test_retry_after_follows_the_breaker_window(make_client, signer, redis, clock, monkeypatch):
    monkeypatch.setenv(sr.BREAKER_ENV, "10")
    client = make_client(fail_mode="split")
    redis.fail = True
    r = await client.post("/r", headers=auth(signer))
    assert r.status_code == 503 and r.headers["retry-after"] == "10"


async def test_split_sensitive_route_fails_closed_even_for_a_get_inside_the_window(make_client, signer, redis, clock):
    client = make_client(fail_mode="split")
    h = auth(signer)
    assert (await client.get("/export", headers=h)).status_code == 200
    redis.fail = True
    assert (await client.get("/export", headers=h)).status_code == 503
    assert (await client.get("/r", headers=h)).status_code == 200  # same session, plain GET, still inside the window


async def test_request_state_mark_from_an_admin_permission_route_counts_as_sensitive(make_client, signer, redis, clock):
    client = make_client(fail_mode="split")
    h = auth(signer)
    assert (await client.get("/admin-marked", headers=h)).status_code == 200
    redis.fail = True
    assert (await client.get("/admin-marked", headers=h)).status_code == 503


async def test_a_breaker_window_does_not_let_writes_through_in_split(make_client, signer, redis, clock, monkeypatch):
    monkeypatch.setenv(sr.BREAKER_ENV, "10")
    client = make_client(fail_mode="split")
    redis.fail = True
    h = auth(signer)
    assert (await client.post("/r", headers=h)).status_code == 503   # the failure that opens the window
    reads = redis.reads
    assert (await client.post("/r", headers=h)).status_code == 503   # skipped request: store not asked, still refused
    assert redis.reads == reads
    # ... while in "open" mode the same skipped request passes (unchanged behaviour)
    client2 = make_client(fail_mode="open")
    assert (await client2.post("/r", headers=auth(signer))).status_code == 200
    assert (await client2.post("/r", headers=auth(signer))).status_code == 200


# ─── split: safe reads, bounded ───────────────────────────────────────────────

@pytest.mark.parametrize("method", ["GET", "HEAD", "OPTIONS"])
async def test_split_safe_reads_use_the_last_known_status_inside_the_window(make_client, signer, redis, clock, method):
    client = make_client(fail_mode="split")
    h = auth(signer)
    assert (await client.get("/r", headers=h)).status_code == 200
    redis.fail = True
    clock.now += 299
    assert (await client.request(method, "/r", headers=h)).status_code == 200
    assert metrics.session_snapshot()["stale_read_served"] == 1


async def test_split_reads_fail_closed_after_the_stale_window(make_client, signer, redis, clock):
    client = make_client(fail_mode="split", stale_read_seconds=300)
    h = auth(signer)
    assert (await client.get("/r", headers=h)).status_code == 200
    redis.fail = True
    clock.now += 301
    r = await client.get("/r", headers=h)
    assert r.status_code == 503 and "retry-after" in r.headers


async def test_split_window_is_measured_from_the_last_successful_check_not_the_last_failure(make_client, signer, redis, clock):
    client = make_client(fail_mode="split", stale_read_seconds=300)
    h = auth(signer)
    await client.get("/r", headers=h)
    redis.fail = True
    for _ in range(4):  # four failures 100 s apart: the window does not restart
        clock.now += 100
        status = (await client.get("/r", headers=h)).status_code
    assert status == 503


async def test_split_read_with_no_successful_check_yet_fails_closed(make_client, signer, redis, clock):
    client = make_client(fail_mode="split")
    redis.fail = True
    assert (await client.get("/r", headers=auth(signer))).status_code == 503


async def test_split_stale_seconds_zero_means_reads_fail_closed_at_once(make_client, signer, redis, clock):
    client = make_client(fail_mode="split", stale_read_seconds=0)
    h = auth(signer)
    await client.get("/r", headers=h)
    redis.fail = True
    clock.now += 1
    assert (await client.get("/r", headers=h)).status_code == 503


async def test_a_session_seen_revoked_stays_revoked_during_the_outage(make_client, signer, redis, clock):
    client = make_client(fail_mode="split")
    uid = uuid.uuid4()
    h = auth(signer, uid)
    redis.revoke(uid, datetime.now(UTC) + timedelta(seconds=30))
    assert (await client.get("/r", headers=h)).status_code == 401
    redis.fail = True
    r = await client.get("/r", headers=h)
    assert r.status_code == 401  # not 200 from the stale window, not 503


async def test_split_malformed_marker_is_refused_401_like_closed(make_client, signer, redis, clock):
    client = make_client(fail_mode="split")
    uid = uuid.uuid4()
    redis.store[f"session_revoked_at:{uid}"] = "not-a-date"
    assert (await client.get("/r", headers=auth(signer, uid))).status_code == 401


async def test_split_unavailable_logs_the_outcome_with_its_fields(make_client, signer, redis, clock, caplog):
    client = make_client(fail_mode="split")
    redis.fail = True
    with caplog.at_level(logging.WARNING, logger=LOGGER):
        await client.post("/r", headers=auth(signer))
    rec = [r for r in caplog.records if r.getMessage() == "revocation_store_unavailable"]
    assert len(rec) == 1
    assert rec[0].outcome == "rejected_unavailable" and rec[0].fail_mode == "split" and rec[0].method == "POST"
    assert rec[0].sensitive is False


async def test_warn_mode_never_rejects_even_in_split(make_client, signer, redis, clock):
    client = make_client(mode="warn", fail_mode="split")
    redis.fail = True
    assert (await client.post("/r", headers=auth(signer))).status_code == 200


# ─── existing modes unchanged ─────────────────────────────────────────────────

async def test_open_and_closed_keep_their_behaviour(make_client, signer, redis, clock):
    redis.fail = True
    assert (await make_client(fail_mode="open").post("/r", headers=auth(signer))).status_code == 200
    r = await make_client(fail_mode="closed").get("/r", headers=auth(signer))
    assert r.status_code == 401 and "retry-after" not in r.headers


def test_library_default_is_still_open(monkeypatch):
    pytest.importorskip("redis")
    sr.configure_session_revocation("redis://localhost:1/0", mode="enforce")
    assert sr._checker.fail_mode == "open" and sr._checker.cache_seconds == 0
    sr.reset_session_revocation()


def test_configure_reads_the_split_env_and_validates(monkeypatch):
    pytest.importorskip("redis")
    monkeypatch.setenv(sr.FAIL_MODE_ENV, "split")
    monkeypatch.setenv(sr.STALE_READ_ENV, "120")
    monkeypatch.setenv(sr.CACHE_SECONDS_ENV, "3")
    monkeypatch.setenv(sr.CACHE_MAX_ENTRIES_ENV, "50")
    sr.configure_session_revocation("redis://localhost:1/0", mode="enforce")
    c = sr._checker
    assert (c.fail_mode, c.stale_read_seconds, c.cache_seconds, c.cache_max_entries) == ("split", 120.0, 3.0, 50)
    monkeypatch.setenv(sr.STALE_READ_ENV, "999999")
    sr.configure_session_revocation("redis://localhost:1/0", mode="enforce")
    assert sr._checker.stale_read_seconds == sr.MAX_STALE_READ_SECONDS
    with pytest.raises(ValueError):
        sr.configure_session_revocation("redis://localhost:1/0", fail_mode="sometimes")  # type: ignore[arg-type]
    sr.reset_session_revocation()


# ─── status cache ─────────────────────────────────────────────────────────────

async def test_cache_off_reads_the_store_every_time_exactly_as_before(make_client, signer, redis, clock):
    client = make_client()
    h = auth(signer)
    for _ in range(100):
        assert (await client.get("/r", headers=h)).status_code == 200
    assert redis.reads == 100
    snap = metrics.session_snapshot()
    assert snap == {"store_reads": 100}  # no cache_hit / cache_miss: the cache layer is not involved
    assert not sr._checker._valid and not sr._checker._inflight


async def test_cache_on_100_sequential_requests_make_one_store_read(make_client, signer, redis, clock):
    client = make_client(cache_seconds=3)
    h = auth(signer)
    for _ in range(100):
        assert (await client.get("/r", headers=h)).status_code == 200
    assert redis.reads == 1
    assert metrics.session_snapshot() == {"cache_miss": 1, "store_reads": 1, "cache_hit": 99}


async def test_concurrent_requests_for_one_session_share_one_store_read(make_client, signer, redis, clock):
    redis.delay = 0.05
    client = make_client(cache_seconds=3)
    h = auth(signer)
    results = await asyncio.gather(*[client.get("/r", headers=h) for _ in range(50)])
    assert {r.status_code for r in results} == {200}
    assert redis.reads == 1
    assert metrics.session_snapshot()["store_reads"] == 1


async def test_different_sessions_of_one_user_and_different_users_are_separate_keys(make_client, signer, redis, clock):
    client = make_client(cache_seconds=3)
    uid = uuid.uuid4()
    await client.get("/r", headers=auth(signer, uid))
    await client.get("/r", headers=auth(signer, uid))        # another token (jti) for the same user
    await client.get("/r", headers=auth(signer))            # another user
    assert redis.reads == 3


async def test_a_revocation_becomes_visible_within_the_ttl(make_client, signer, redis, clock):
    client = make_client(cache_seconds=3)
    uid = uuid.uuid4()
    h = auth(signer, uid)
    assert (await client.get("/r", headers=h)).status_code == 200
    redis.revoke(uid, datetime.now(UTC) + timedelta(seconds=30))
    clock.now += 1.0
    assert (await client.get("/r", headers=h)).status_code == 200   # inside the TTL the old answer stands (documented)
    clock.now += 2.01                                                # 3.01 s: past the longest possible TTL
    assert (await client.get("/r", headers=h)).status_code == 401
    assert redis.reads == 2


async def test_a_revoked_answer_is_cached_for_its_full_life(make_client, signer, redis, clock):
    client = make_client(cache_seconds=3)
    uid = uuid.uuid4()
    h = auth(signer, uid)
    redis.revoke(uid, datetime.now(UTC) + timedelta(seconds=30))
    assert (await client.get("/r", headers=h)).status_code == 401
    reads = redis.reads
    clock.now += 3600  # long past the valid-answer TTL
    assert (await client.get("/r", headers=h)).status_code == 401
    assert redis.reads == reads
    assert metrics.session_snapshot()["cache_hit"] == 1


async def test_valid_entries_expire_with_jitter_never_beyond_the_ttl(make_client, signer, redis, clock):
    client = make_client(cache_seconds=10)
    for _ in range(30):
        await client.get("/r", headers=auth(signer))
    lives = [exp - clock.now for exp in sr._checker._valid.values()]
    assert all(8.0 <= life <= 10.0 for life in lives)
    assert len({round(life, 6) for life in lives}) > 1, "expiries are spread, not identical"


async def test_cache_is_bounded_lru(make_client, signer, redis, clock):
    client = make_client(cache_seconds=60, cache_max_entries=3)
    hs = [auth(signer) for _ in range(5)]
    for h in hs:
        await client.get("/r", headers=h)
    assert len(sr._checker._valid) == 3
    await client.get("/r", headers=hs[4])          # newest still cached
    assert redis.reads == 5
    await client.get("/r", headers=hs[0])          # oldest was evicted -> read again
    assert redis.reads == 6


async def test_unavailable_is_never_cached_as_valid_split(make_client, signer, redis, clock):
    client = make_client(fail_mode="split", cache_seconds=3)
    h = auth(signer)
    redis.fail = True
    assert (await client.post("/r", headers=h)).status_code == 503
    assert (await client.post("/r", headers=h)).status_code == 503   # not remembered as valid: asked (and refused) again
    assert redis.reads == 2
    assert not sr._checker._valid
    redis.fail = False
    assert (await client.post("/r", headers=h)).status_code == 200   # recovers at once


async def test_stale_read_during_outage_does_not_populate_the_cache(make_client, signer, redis, clock):
    client = make_client(fail_mode="split", cache_seconds=3)
    await client.get("/r", headers=auth(signer))                       # success: last_ok set
    h = auth(signer)
    redis.fail = True
    assert (await client.get("/r", headers=h)).status_code == 200      # stale read, inside the window
    reads = redis.reads
    assert (await client.get("/r", headers=h)).status_code == 200
    assert redis.reads == reads + 1, "the stale answer was not cached: the store is asked again"
    assert len(sr._checker._valid) == 1


async def test_a_cached_valid_answer_hides_an_outage_for_its_ttl_only_then_the_policy_applies(make_client, signer, redis, clock):
    client = make_client(fail_mode="split", cache_seconds=3)
    h = auth(signer)
    await client.post("/r", headers=h)
    redis.fail = True
    assert (await client.post("/r", headers=h)).status_code == 200      # fresh cached valid answer (<= 3 s old)
    clock.now += 3.01
    assert (await client.post("/r", headers=h)).status_code == 503      # expired -> store asked -> write fails closed


async def test_sensitive_routes_bypass_the_cache(make_client, signer, redis, clock):
    client = make_client(cache_seconds=3)
    uid = uuid.uuid4()
    h = auth(signer, uid)
    assert (await client.get("/r", headers=h)).status_code == 200
    redis.revoke(uid, datetime.now(UTC) + timedelta(seconds=30))
    assert (await client.get("/r", headers=h)).status_code == 200       # cached
    assert (await client.get("/export", headers=h)).status_code == 401  # sensitive: fresh read sees the marker


async def test_a_cancelled_waiter_does_not_cancel_the_shared_read(make_client, signer, redis, clock):
    redis.delay = 0.1
    client = make_client(cache_seconds=3)
    h = auth(signer)
    first = asyncio.ensure_future(client.get("/r", headers=h))
    second = asyncio.ensure_future(client.get("/r", headers=h))
    await asyncio.sleep(0.02)
    first.cancel()
    assert (await second).status_code == 200
    assert redis.reads == 1


async def test_require_permission_admin_marks_the_request_sensitive_for_a_later_revocation_check(signer, redis, clock):
    build_app(signer, redis, fail_mode="split")          # configures the checker, jwks and error handler
    blumax_auth.configure_permissions(
        core_url="http://core:8000", ttl_seconds=0,
        transport=httpx.MockTransport(lambda _r: httpx.Response(200, json={"permissions": ["x.admin", "x.view"]})),
    )
    app = FastAPI()
    blumax_auth.install_error_handler(app)
    Check = Annotated[None, Depends(sr.check_session_revocation)]  # noqa: N806

    @app.get("/admin")
    async def admin(_p=Depends(blumax_auth.require_permission("x.admin", admin=True)), _c: Check = None) -> dict:
        return {"ok": True}

    @app.get("/plain")
    async def plain(_p=Depends(blumax_auth.require_permission("x.view")), _c: Check = None) -> dict:
        return {"ok": True}

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as c:
        h = auth(signer)
        assert (await c.get("/admin", headers=h)).status_code == 200
        assert (await c.get("/plain", headers=h)).status_code == 200
        redis.fail = True
        assert (await c.get("/plain", headers=h)).status_code == 200    # safe read inside the window
        assert (await c.get("/admin", headers=h)).status_code == 503    # admin route: fail closed
    blumax_auth.reset_permissions()
    blumax_auth.reset_session_revocation()
    blumax_auth.reset()
