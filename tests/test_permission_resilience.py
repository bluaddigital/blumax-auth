"""0.5.2 permission-client resilience: C3 retry once on no answer (IMP-DEP-4), C4 bounded
stale-on-error (IMP-DEP-5), the breaker staying in charge, and the optional O9 counter.

Core is the FakeCore from test_permissions (httpx.MockTransport); time is a fake clock.
"""
from __future__ import annotations

import logging
import sys
import uuid
from datetime import UTC, datetime, timedelta
from typing import Annotated

import httpx
import pytest
from fastapi import Depends, FastAPI
from test_permissions import CODE, CORE, FakeClock, FakeCore
from test_session_revocation import FakeRedis
from test_session_revocation import _configure as _configure_revocation
from test_verification import AUDIENCE, ISSUER, Signer

import blumax_auth
from blumax_auth import AuthContext, metrics
from blumax_auth import permissions as perm
from blumax_auth.errors import Forbidden, InvalidToken
from blumax_auth.permissions import MAX_STALE_GRACE_SECONDS, PermissionCheckUnavailable, _Checker
from blumax_auth.session_revocation import check_session_revocation

TTL = 30.0


@pytest.fixture(autouse=True)
def _fresh_metrics(monkeypatch):
    monkeypatch.delenv(metrics.ENV_FLAG, raising=False)
    metrics.reset_metrics()
    yield
    metrics.reset_metrics()


def _ctx(user: uuid.UUID | None = None, tenant: uuid.UUID | None = None) -> AuthContext:
    return AuthContext(
        user_id=user or uuid.uuid4(), tenant_id=tenant or uuid.uuid4(), tenant_slug="t", role="CLINICIAN",
        archetype="CLINICIAN", facility_ids=None, person_id=None, provider_id=None, is_platform_admin=False,
        jti="j",
    )


def _checker(core: FakeCore, clock: FakeClock, **over) -> _Checker:
    kwargs = dict(
        core_url=CORE, ttl_seconds=TTL, timeout_seconds=2.0, max_entries=100,
        transport=httpx.MockTransport(core.handle), clock=clock,
        breaker_failures=5, breaker_open_seconds=10.0,
        retry_on_no_answer=True, retry_pause_seconds=0.0, stale_grace_seconds=0.0,
    )
    kwargs.update(over)
    return _Checker(**kwargs)


class FlakyCore(FakeCore):
    """FakeCore whose first N asks raise `fail`, then answer normally."""

    def __init__(self, fail: Exception, times: int) -> None:
        super().__init__()
        self._fail, self._times = fail, times

    async def handle(self, request: httpx.Request) -> httpx.Response:
        if self._times > 0:
            self._times -= 1
            self.requests.append(request)
            raise self._fail
        return await super().handle(request)


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


# ─── defaults ─────────────────────────────────────────────────────────────────

def test_configure_defaults_retry_on_stale_off_breaker_5_10():
    blumax_auth.configure_permissions(core_url=CORE)
    try:
        c = perm._checker
        assert c._retry is True and c._retry_pause == 0.15
        assert c._grace == 0.0
        assert (c._breaker_limit, c._breaker_open_seconds) == (5, 10.0)
    finally:
        blumax_auth.reset_permissions()


def test_grace_is_clamped_to_120_with_a_warning(caplog):
    with caplog.at_level(logging.WARNING, logger="blumax_auth.permissions"):
        blumax_auth.configure_permissions(core_url=CORE, stale_grace_seconds=600)
    try:
        assert perm._checker._grace == MAX_STALE_GRACE_SECONDS == 120.0
        assert any(r.getMessage() == "permission_stale_grace_clamped" for r in caplog.records)
    finally:
        blumax_auth.reset_permissions()


@pytest.mark.parametrize("bad", [{"stale_grace_seconds": -1}, {"retry_pause_seconds": -0.1}])
def test_negative_settings_are_refused(bad):
    with pytest.raises(ValueError):
        blumax_auth.configure_permissions(core_url=CORE, **bad)


def test_version_is_0_6_1():
    assert blumax_auth.__version__ == "0.6.1"


# ─── C3: retry once on NO answer ──────────────────────────────────────────────

class TestRetry:
    @pytest.mark.parametrize("fail", [httpx.ReadTimeout("slow"), httpx.ConnectError("refused")])
    async def test_one_retry_on_no_answer_then_the_answer_counts(self, clock, fail):
        core = FlakyCore(fail, times=1)
        core.grant("tok", CODE)
        answer = await _checker(core, clock).granted(_ctx(), "tok")
        assert CODE in answer.codes and core.calls == 2
        assert metrics.snapshot()["retried"] == 1 and metrics.snapshot()["ok"] == 1

    async def test_only_one_retry_then_fail_closed(self, clock):
        core = FakeCore()
        core.fail = httpx.ReadTimeout("slow")
        with pytest.raises(PermissionCheckUnavailable):
            await _checker(core, clock).granted(_ctx(), "tok")
        assert core.calls == 2
        assert metrics.snapshot() == {"timeout": 2, "retried": 1}

    @pytest.mark.parametrize("status,body,exc", [
        (401, {}, InvalidToken), (403, {}, Forbidden), (404, {}, Forbidden),
        (500, {}, PermissionCheckUnavailable), (502, "bad gateway", PermissionCheckUnavailable),
        (503, {}, PermissionCheckUnavailable), (200, {"unexpected": 1}, PermissionCheckUnavailable),
    ])
    async def test_never_retried_when_core_answered(self, clock, status, body, exc):
        core = FakeCore()
        core.respond("tok", status, body)
        with pytest.raises(exc):
            await _checker(core, clock).granted(_ctx(), "tok")
        assert core.calls == 1
        assert "retried" not in metrics.snapshot()

    async def test_switch_off(self, clock):
        core = FakeCore()
        core.fail = httpx.ConnectError("refused")
        with pytest.raises(PermissionCheckUnavailable):
            await _checker(core, clock, retry_on_no_answer=False).granted(_ctx(), "tok")
        assert core.calls == 1

    async def test_not_retried_once_the_breaker_opened(self, clock):
        core = FakeCore()
        core.fail = httpx.ConnectError("refused")
        checker = _checker(core, clock, breaker_failures=1)
        with pytest.raises(PermissionCheckUnavailable):
            await checker.granted(_ctx(), "tok")
        assert core.calls == 1                       # the first failure opened it: no second ask
        with pytest.raises(PermissionCheckUnavailable):
            await checker.granted(_ctx(), "tok2")
        assert core.calls == 1                       # open: refused locally
        assert metrics.snapshot()["breaker_open"] == 1

    async def test_each_failed_attempt_counts_towards_the_breaker(self, clock):
        core = FakeCore()
        core.fail = httpx.ConnectError("refused")
        checker = _checker(core, clock, breaker_failures=4)
        for _ in range(2):                           # 2 lookups x 2 attempts = 4 failures
            with pytest.raises(PermissionCheckUnavailable):
                await checker.granted(_ctx(), "tok")
        assert checker._breaker_is_open()

    async def test_a_refusal_on_the_retry_is_raised_as_itself(self, clock):
        core = FlakyCore(httpx.ReadTimeout("slow"), times=1)
        core.respond("tok", 403)
        with pytest.raises(Forbidden):
            await _checker(core, clock).granted(_ctx(), "tok")


# ─── C4: bounded stale-on-error ───────────────────────────────────────────────

class TestStale:
    async def _held_then_expired(self, core, clock, checker, ctx, token="tok", *codes):
        core.grant(token, *(codes or (CODE,)))
        await checker.granted(ctx, token)            # one success, cached
        clock.advance(TTL + 5)                        # the cache entry has expired

    async def test_off_by_default(self, clock):
        core, ctx = FakeCore(), _ctx()
        checker = _checker(core, clock)
        await self._held_then_expired(core, clock, checker, ctx)
        core.fail = httpx.ConnectError("down")
        with pytest.raises(PermissionCheckUnavailable):
            await checker.granted(ctx, "tok")

    @pytest.mark.parametrize("outage", ["timeout", "connect", "500", "503"])
    async def test_serves_the_last_answer_inside_the_grace_with_log_and_counter(self, clock, caplog, outage):
        core, ctx = FakeCore(), _ctx()
        checker = _checker(core, clock, stale_grace_seconds=60)
        await self._held_then_expired(core, clock, checker, ctx)
        if outage == "timeout":
            core.fail = httpx.ReadTimeout("slow")
        elif outage == "connect":
            core.fail = httpx.ConnectError("down")
        else:
            core.respond("tok", int(outage))
        with caplog.at_level(logging.WARNING, logger="blumax_auth.permissions"):
            answer = await checker.granted(ctx, "tok")
        assert CODE in answer.codes and answer.cached
        recs = [r for r in caplog.records if r.getMessage() == "permission_check_served_stale"]
        assert len(recs) == 1 and recs[0].user_id == str(ctx.user_id) and recs[0].seconds_past_expiry == 5.0
        assert metrics.snapshot()["stale_served"] == 1

    async def test_a_held_deny_is_served_as_a_deny(self, clock):
        core, ctx = FakeCore(), _ctx()
        checker = _checker(core, clock, stale_grace_seconds=60)
        await self._held_then_expired(core, clock, checker, ctx, "tok", "something.else")
        core.fail = httpx.ConnectError("down")
        assert CODE not in (await checker.granted(ctx, "tok")).codes

    async def test_not_past_the_grace(self, clock):
        core, ctx = FakeCore(), _ctx()
        checker = _checker(core, clock, stale_grace_seconds=60)
        await self._held_then_expired(core, clock, checker, ctx)
        clock.advance(55)                             # 60 s past expiry
        core.fail = httpx.ConnectError("down")
        with pytest.raises(PermissionCheckUnavailable):
            await checker.granted(ctx, "tok")

    async def test_never_without_a_prior_success_for_the_same_key(self, clock):
        core, ctx = FakeCore(), _ctx()
        checker = _checker(core, clock, stale_grace_seconds=60)
        await self._held_then_expired(core, clock, checker, ctx)
        core.fail = httpx.ConnectError("down")
        for other_ctx, token in [
            (_ctx(), "tok-other-user"),                                     # nobody else's answer
            (_ctx(user=ctx.user_id, tenant=ctx.tenant_id), "tok-2"),        # same user, other token
            (_ctx(user=ctx.user_id), "tok"),                                # same token, other tenant
        ]:
            with pytest.raises(PermissionCheckUnavailable):
                await checker.granted(other_ctx, token)

    @pytest.mark.parametrize("status,exc", [(403, Forbidden), (404, Forbidden), (401, InvalidToken)])
    async def test_never_after_core_refused_the_caller(self, clock, status, exc):
        core, ctx = FakeCore(), _ctx()
        checker = _checker(core, clock, stale_grace_seconds=60)
        await self._held_then_expired(core, clock, checker, ctx)
        core.respond("tok", status)
        with pytest.raises(exc):                      # an answer is raised as itself, never replaced by the held one
            await checker.granted(ctx, "tok")
        core.fail = httpx.ConnectError("down")        # then Core goes away
        with pytest.raises(PermissionCheckUnavailable):
            await checker.granted(ctx, "tok")
        assert "stale_served" not in metrics.snapshot()

    async def test_never_on_a_malformed_answer(self, clock):
        core, ctx = FakeCore(), _ctx()
        checker = _checker(core, clock, stale_grace_seconds=60)
        await self._held_then_expired(core, clock, checker, ctx)
        core.respond("tok", 200, {"unexpected": "shape"})
        with pytest.raises(PermissionCheckUnavailable):
            await checker.granted(ctx, "tok")

    async def test_never_for_admin(self, clock):
        core, ctx = FakeCore(), _ctx()
        checker = _checker(core, clock, stale_grace_seconds=60)
        await self._held_then_expired(core, clock, checker, ctx)
        core.fail = httpx.ConnectError("down")
        with pytest.raises(PermissionCheckUnavailable):
            await checker.granted(ctx, "tok", allow_stale=False)

    async def test_served_while_the_breaker_is_open(self, clock):
        core, ctx = FakeCore(), _ctx()
        checker = _checker(core, clock, stale_grace_seconds=60, breaker_failures=1)
        await self._held_then_expired(core, clock, checker, ctx)
        core.fail = httpx.ConnectError("down")
        await checker.granted(ctx, "tok")             # opens the breaker, served stale
        calls = core.calls
        assert CODE in (await checker.granted(ctx, "tok")).codes
        assert core.calls == calls                    # refused locally, still served from the held answer

    async def test_a_fresh_success_replaces_the_held_answer(self, clock):
        core, ctx = FakeCore(), _ctx()
        checker = _checker(core, clock, stale_grace_seconds=60)
        await self._held_then_expired(core, clock, checker, ctx)
        core.grant("tok", "other.code")               # role edited
        await checker.granted(ctx, "tok")
        clock.advance(TTL + 5)
        core.fail = httpx.ConnectError("down")
        assert (await checker.granted(ctx, "tok")).codes == frozenset({"other.code"})

    async def test_nothing_held_when_ttl_is_zero(self, clock):
        core, ctx = FakeCore(), _ctx()
        checker = _checker(core, clock, stale_grace_seconds=60, ttl_seconds=0)
        core.grant("tok", CODE)
        await checker.granted(ctx, "tok")
        core.fail = httpx.ConnectError("down")
        with pytest.raises(PermissionCheckUnavailable):
            await checker.granted(ctx, "tok")


# ─── through FastAPI: admin routes, session revocation, token expiry ──────────

Consult = Annotated[AuthContext, Depends(blumax_auth.require_permission(CODE))]
AdminConsult = Annotated[AuthContext, Depends(blumax_auth.require_permission(CODE, admin=True))]
Revocation = Annotated[None, Depends(check_session_revocation)]


@pytest.fixture
def signer() -> Signer:
    return Signer()


@pytest.fixture
def redis() -> FakeRedis:
    return FakeRedis()


@pytest.fixture
async def client(signer, clock, redis):
    core = FakeCore()
    blumax_auth.reset()
    blumax_auth.reset_permissions()
    blumax_auth.reset_session_revocation()
    blumax_auth.configure(jwks_url="http://unused.invalid/jwks.json", issuer=ISSUER, audience=AUDIENCE)
    blumax_auth.jwks_cache().seed(signer.jwks())
    blumax_auth.configure_permissions(
        core_url=CORE, ttl_seconds=TTL, transport=httpx.MockTransport(core.handle), clock=clock,
        retry_pause_seconds=0.0, stale_grace_seconds=120,
    )
    _configure_revocation(redis, mode="enforce")

    app = FastAPI()
    blumax_auth.install_error_handler(app)

    @app.get("/consult")
    async def consult(ctx: Consult, _: Revocation) -> dict:
        return {"ok": True}

    @app.get("/admin")
    async def admin(ctx: AdminConsult, _: Revocation) -> dict:
        return {"ok": True}

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as c:
        c.core = core
        yield c
    blumax_auth.reset_permissions()
    blumax_auth.reset_session_revocation()
    blumax_auth.reset()


async def _warm_then_outage(client, clock, token):
    client.core.grant(token, CODE)
    h = {"Authorization": f"Bearer {token}"}
    assert (await client.get("/consult", headers=h)).status_code == 200
    assert (await client.get("/admin", headers=h)).status_code == 200
    clock.advance(TTL + 10)
    client.core.fail = httpx.ConnectError("down")
    return h


async def test_route_stale_serve_but_never_on_admin_route(client, clock, signer):
    h = await _warm_then_outage(client, clock, signer.token())
    assert (await client.get("/consult", headers=h)).status_code == 200
    r = await client.get("/admin", headers=h)
    assert r.status_code == 503 and r.json()["error"]["code"] == "PERMISSION_CHECK_UNAVAILABLE"


async def test_session_revocation_still_refuses_while_stale_is_on(client, clock, signer, redis):
    claims_iat = datetime.now(UTC) - timedelta(minutes=1)
    token = signer.token(iat=claims_iat)
    h = await _warm_then_outage(client, clock, token)
    sub = (await blumax_auth.verifier().verify(token)).user_id
    redis.revoke(sub, datetime.now(UTC))
    assert (await client.get("/consult", headers=h)).status_code == 401


# ─── O9: optional counter ─────────────────────────────────────────────────────

class TestMetrics:
    def test_prometheus_untouched_when_flag_off(self):
        metrics.core_permission_call("ok")
        assert metrics.snapshot() == {"ok": 1}
        assert metrics._prom is None

    def test_exposed_when_flag_on(self, monkeypatch):
        REGISTRY = pytest.importorskip("prometheus_client").REGISTRY

        monkeypatch.setenv(metrics.ENV_FLAG, "true")
        before = REGISTRY.get_sample_value("blumax_core_permission_calls_total", {"outcome": "stale_served"}) or 0.0
        metrics.core_permission_call("stale_served")
        after = REGISTRY.get_sample_value("blumax_core_permission_calls_total", {"outcome": "stale_served"})
        assert after == before + 1

    def test_flag_on_without_prometheus_is_a_warning_not_an_error(self, monkeypatch, caplog):
        monkeypatch.setenv(metrics.ENV_FLAG, "true")
        monkeypatch.setitem(sys.modules, "prometheus_client", None)   # import fails
        with caplog.at_level(logging.WARNING, logger="blumax_auth.metrics"):
            metrics.core_permission_call("ok")
            metrics.core_permission_call("ok")
        assert metrics.snapshot() == {"ok": 2}
        assert [r.getMessage() for r in caplog.records].count("metrics_unavailable") == 1

    def test_unknown_outcome_is_kept_out_of_the_label_set(self):
        metrics.core_permission_call("tenant-123")
        assert metrics.snapshot() == {"unknown": 1}


async def test_a_0_5_1_style_granted_wrapper_still_works_on_non_admin_routes(client, clock, signer):
    """IPD/OPD wrap `checker.granted(ctx, token)` (two arguments); 0.5.2 must not pass them a keyword they don't take."""
    checker = perm._checker
    original = checker.granted

    async def wrapped(ctx, token):
        return await original(ctx, token)

    checker.granted = wrapped
    token = signer.token()
    client.core.grant(token, CODE)
    assert (await client.get("/consult", headers={"Authorization": f"Bearer {token}"})).status_code == 200
