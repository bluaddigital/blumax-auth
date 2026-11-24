"""Local evaluation still applies in services that wrap `_Checker.granted` (IPD / OPD app/core/permission_resilience.py).

`opd_install` below is blumax-opd origin/dev app/core/permission_resilience.install() copied VERBATIM (IPD's copy is the
same function): it replaces `checker.granted` and `checker._store` on the configured checker with a retry + stale-on-error
wrapper. The local decision is taken in permissions._decide(), ABOVE `granted`, so:

  local   a usable token answer never reaches `granted` (wrapped or not): Core is not asked;
          a fallback goes through the WRAPPED `granted`, so the wrapper's retry / stale serving still apply there.
  shadow  Core (through the wrapped `granted`) decides, the token's answer is compared, exactly as without a wrapper.
  off     the wrapped `granted` is the whole story, as before: no catalogue, no Redis, no local log line.
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
from collections import OrderedDict
from typing import Any

import httpx
import pytest
from test_local_permissions import (
    CATALOGUE,
    HELD,
    LOGGER,
    PERMS,
    FakeClock,
    FakeCore,
    FakeRedis,
    bearer,
    build_app,
    configure,
    local_records,
    mint,
)

import blumax_auth
from blumax_auth import metrics
from blumax_auth import permissions as _lib
from blumax_auth import session_revocation as sr
from blumax_auth.permissions import PermissionCheckUnavailable

WRAPPER_LOGGER = "opd.permission_resilience"
_log = logging.getLogger(WRAPPER_LOGGER)

# ─── blumax-opd app/core/permission_resilience.py install(), verbatim (module globals inlined above/below) ──────────

_REQUIRED = ("granted", "_store", "_clock", "_ttl")


def _no_answer(exc: BaseException) -> bool:
    return getattr(exc, "core_status", None) is None


def _may_serve_stale(exc: BaseException) -> bool:
    status = getattr(exc, "core_status", None)
    return status is None or status >= 500


def opd_install(*, retry: bool, retry_pause_seconds: float, stale_grace_seconds: float, max_entries: int = 10_000) -> bool:
    """Wrap the checker blumax_auth.configure_permissions() just built. Call right after it. True when installed."""
    checker = _lib._checker
    if checker is None:
        return False
    if getattr(checker, "_permission_resilience_installed", False):
        return True
    if not all(hasattr(checker, name) for name in _REQUIRED) or not hasattr(_lib, "_Answer"):
        _log.error("permission_resilience_unavailable", extra={"missing": [n for n in _REQUIRED if not hasattr(checker, n)]})
        return False

    original_granted = checker.granted
    original_store = checker._store
    clock = checker._clock
    grace = max(0.0, float(stale_grace_seconds))
    # key -> (the library entry's expiry, codes). One constant TTL, so insertion order is expiry order and the oldest is first.
    last_good: OrderedDict[Any, tuple[float, frozenset[str]]] = OrderedDict()

    def _store(key: Any, codes: frozenset[str]) -> None:
        original_store(key, codes)
        if grace <= 0 or checker._ttl <= 0:  # no cache, nothing to fall back on
            return
        now = clock()
        last_good[key] = (now + checker._ttl, codes)
        last_good.move_to_end(key)
        while last_good and next(iter(last_good.values()))[0] + grace <= now:
            last_good.popitem(last=False)
        while len(last_good) > max_entries:
            last_good.popitem(last=False)

    async def granted(ctx: Any, token: str) -> Any:
        try:
            return await original_granted(ctx, token)
        except PermissionCheckUnavailable as exc:
            failure: PermissionCheckUnavailable = exc
        if retry and _no_answer(failure):
            _log.info("permission_check_retry", extra={"tenant_id": str(ctx.tenant_id)})
            await asyncio.sleep(retry_pause_seconds)
            try:
                return await original_granted(ctx, token)  # a Core 401/403 on the retry propagates as itself
            except PermissionCheckUnavailable as exc:
                failure = exc
        if grace > 0 and _may_serve_stale(failure):
            key = (ctx.tenant_id, ctx.user_id, hashlib.sha256(token.encode()).hexdigest())
            entry = last_good.get(key)
            if entry is not None:
                expires_at, codes = entry
                now = clock()
                if now < expires_at + grace:
                    _log.warning(
                        "permission_check_served_stale",
                        extra={
                            "tenant_id": str(ctx.tenant_id), "user_id": str(ctx.user_id),
                            "seconds_past_expiry": round(max(0.0, now - expires_at), 1),
                            "core_status": getattr(failure, "core_status", None),
                        },
                    )
                    return _lib._Answer(codes=codes, cached=True)
        raise failure

    checker.granted = granted  # type: ignore[method-assign]
    checker._store = _store  # type: ignore[method-assign]
    checker._permission_resilience_installed = True  # type: ignore[attr-defined]
    return True


# ─── Harness ──────────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    for name in ("PERMISSION_LOCAL_MODE", "PERMISSION_AUTHZ_VER_REDIS_URL", "PERMISSION_AUTHZ_VER_CACHE_SECONDS",
                 "PERMISSION_CATALOGUE_TIMEOUT_SECONDS"):
        monkeypatch.delenv(name, raising=False)
    metrics.reset_metrics()
    sr.reset_session_revocation()
    yield
    metrics.reset_metrics()
    sr.reset_session_revocation()
    blumax_auth.reset_permissions()
    blumax_auth.reset()


class CountingGranted:
    """Counts calls into the (already wrapped) checker.granted -- i.e. how often the wrapper is reached."""

    def __init__(self) -> None:
        checker = _lib._checker
        assert checker is not None
        self.calls = 0
        inner = checker.granted

        async def counted(ctx: Any, token: str, **kw: Any) -> Any:
            self.calls += 1
            return await inner(ctx, token, **kw)

        checker.granted = counted  # type: ignore[method-assign]


def setup(core: FakeCore, clock: FakeClock, redis: FakeRedis, mode: str | None, **over: Any) -> CountingGranted:
    kwargs: dict[str, Any] = {"retry_on_no_answer": False}  # leave the retry to the wrapper, so it is observable
    kwargs.update(over)
    if mode is not None:
        kwargs["local_mode"] = mode
    configure(core, clock, redis, **kwargs)
    assert opd_install(retry=True, retry_pause_seconds=0.0, stale_grace_seconds=60.0) is True
    return CountingGranted()


async def settle() -> None:
    """Let a background catalogue preload (if any) finish."""
    checker = _lib._checker
    local = getattr(checker, "local", None)
    task = getattr(local, "_cat_task", None)
    if task is not None:
        await asyncio.wait([task])
    await asyncio.sleep(0)


@pytest.fixture
async def app_client(signer):
    app = build_app(signer)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as c:
        yield c


@pytest.fixture
def signer():
    from test_verification import Signer
    return Signer()


# ─── Tests ────────────────────────────────────────────────────────────────────

class TestWrappedLocal:
    async def test_token_decides_without_reaching_the_wrapper(self, app_client, signer):
        core, clock, redis = FakeCore(), FakeClock(), FakeRedis()
        counted = setup(core, clock, redis, "local")
        warm = mint(signer)
        core.grant(warm, HELD)
        await app_client.get("/held", headers=bearer(warm))  # first use: loads the catalogue
        await settle()
        before_perms, before_wrapper = core.calls(PERMS), counted.calls
        metrics.reset_metrics()

        token = mint(signer, codes=(HELD,))
        assert (await app_client.get("/held", headers=bearer(token))).status_code == 200
        assert (await app_client.get("/not-held", headers=bearer(token))).status_code == 403
        assert core.calls(PERMS) == before_perms and counted.calls == before_wrapper  # Core never asked, wrapper never reached
        assert metrics.local_snapshot() == {"local_allow": 1, "local_deny": 1}
        assert core.calls(CATALOGUE) == 1

    async def test_fallback_goes_through_the_wrapper_retry(self, app_client, signer, caplog):
        core, clock, redis = FakeCore(), FakeClock(), FakeRedis()
        token = mint(signer, v2=False)  # fallback v1_token -> Core, through the wrapper
        core.grant(token, HELD)
        failures = {"left": 1}

        async def flaky(request: httpx.Request) -> httpx.Response:
            if request.url.path == PERMS and failures["left"]:
                failures["left"] -= 1
                core.requests.append(request)
                raise httpx.ReadTimeout("slow", request=request)
            return await core.handle(request)

        counted = setup(core, clock, redis, "local", transport=httpx.MockTransport(flaky))
        with caplog.at_level(logging.INFO):
            assert (await app_client.get("/held", headers=bearer(token))).status_code == 200
        assert counted.calls == 1 and core.calls(PERMS) == 2
        assert [r for r in caplog.records if r.name == WRAPPER_LOGGER and r.getMessage() == "permission_check_retry"]
        assert metrics.local_snapshot() == {"fallback:v1_token": 1}

    async def test_fallback_goes_through_the_wrapper_stale_serving(self, app_client, signer, caplog):
        core, clock, redis = FakeCore(), FakeClock(), FakeRedis()
        setup(core, clock, redis, "local")
        token = mint(signer, authz_ver=6)  # stale authz_ver -> fallback -> Core via the wrapper
        core.grant(token, HELD)
        assert (await app_client.get("/held", headers=bearer(token))).status_code == 200
        clock.advance(31)          # library TTL (30 s) gone, inside the wrapper's 60 s grace
        core.perm_status = 500     # Core unwell
        with caplog.at_level(logging.INFO):
            assert (await app_client.get("/held", headers=bearer(token))).status_code == 200
        assert [r for r in caplog.records if r.name == WRAPPER_LOGGER and r.getMessage() == "permission_check_served_stale"]


class TestWrappedShadow:
    async def test_core_via_wrapper_decides_and_local_is_compared(self, app_client, signer):
        core, clock, redis = FakeCore(), FakeClock(), FakeRedis()
        counted = setup(core, clock, redis, "shadow")
        warm = mint(signer)
        core.grant(warm, HELD)
        await app_client.get("/held", headers=bearer(warm))
        await settle()
        metrics.reset_metrics()

        token = mint(signer, codes=(HELD,))
        core.grant(token, HELD)
        assert (await app_client.get("/held", headers=bearer(token))).status_code == 200
        assert (await app_client.get("/not-held", headers=bearer(token))).status_code == 403
        assert counted.calls >= 3  # Core path (wrapped) decides in shadow
        assert metrics.local_snapshot() == {"match": 2}

    async def test_mismatch_reported_through_the_wrapper(self, app_client, signer):
        core, clock, redis = FakeCore(), FakeClock(), FakeRedis()
        setup(core, clock, redis, "shadow")
        warm = mint(signer)
        core.grant(warm, HELD)
        await app_client.get("/held", headers=bearer(warm))
        await settle()
        metrics.reset_metrics()
        token = mint(signer, codes=())   # the token says no
        core.grant(token, HELD)          # Core (through the wrapper) says yes, and wins
        assert (await app_client.get("/held", headers=bearer(token))).status_code == 200
        assert metrics.local_snapshot() == {"mismatch": 1}


class TestWrappedOff:
    @pytest.mark.parametrize("v2", [False, True])
    async def test_off_is_the_wrapped_core_path_only(self, app_client, signer, caplog, v2):
        core, clock, redis = FakeCore(), FakeClock(), FakeRedis()
        with caplog.at_level(logging.DEBUG):
            counted = setup(core, clock, redis, None)  # local_mode omitted, env unset -> off
            token = mint(signer, v2=v2)
            core.grant(token, HELD)
            assert (await app_client.get("/held", headers=bearer(token))).status_code == 200
            assert (await app_client.get("/not-held", headers=bearer(token))).status_code == 403
            await asyncio.sleep(0)
        assert counted.calls == 2 and core.calls(PERMS) == 1
        assert core.calls(CATALOGUE) == 0 and redis.gets == 0
        assert metrics.local_snapshot() == {}
        assert local_records(caplog) == []
        assert [r for r in caplog.records if r.name == LOGGER] == []
        assert _lib._checker.local is None
