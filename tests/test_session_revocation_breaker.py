"""A Redis that hangs costs one timeout, then a short pause (blumax-auth, 2026-11-15).

Before: every authenticated request read Redis twice in a row (the jti exemption, then the marker), each bounded by
the timeout (2 s default), so a Redis that accepted connections but did not answer added ~4 s to EVERY request of
every service for as long as it hung. Now: both keys in one MGET (one timeout), and after a failure Redis is skipped
for SESSION_REVOCATION_BREAKER_SECONDS (fail_mode applies at once, the alert is logged once per window).
"""
from __future__ import annotations

import asyncio
import logging
import time
import uuid
from datetime import UTC, datetime, timedelta

import pytest

import blumax_auth.session_revocation as sr

NOW = datetime.now(UTC)


class _Hung:
    """Accepts the call and never answers (a half-open connection / failover)."""

    def __init__(self, with_mget: bool) -> None:
        self.calls = 0
        if with_mget:
            self.mget = self._hang

    async def _hang(self, *_a):
        self.calls += 1
        await asyncio.Event().wait()

    async def get(self, *_a):
        return await self._hang()


class _Store:
    def __init__(self, data: dict[str, str]) -> None:
        self.data, self.mget_calls = data, 0

    async def mget(self, keys):
        self.mget_calls += 1
        return [self.data.get(k) for k in keys]


@pytest.fixture(autouse=True)
def _short(monkeypatch):
    monkeypatch.setenv("SESSION_REVOCATION_REDIS_TIMEOUT_SECONDS", "0.2")
    monkeypatch.setenv("SESSION_REVOCATION_BREAKER_SECONDS", "10")


@pytest.mark.parametrize("with_mget", [True, False], ids=["real-client-mget", "get-only-double"])
async def test_a_hung_redis_costs_one_timeout_even_with_a_jti(with_mget) -> None:
    redis = _Hung(with_mget)
    checker = sr._Checker(redis, mode="warn")  # type: ignore[arg-type]
    started = time.monotonic()
    assert await checker.is_revoked(uuid.uuid4(), NOW, "jti-1") == (False, "redis_unavailable", None)
    assert time.monotonic() - started < 0.35, "one timeout, not the two reads one after the other"
    assert redis.calls == 1


async def test_the_next_requests_skip_redis_quietly_until_the_window_ends(monkeypatch, caplog) -> None:
    redis = _Hung(True)
    checker = sr._Checker(redis, mode="warn")  # type: ignore[arg-type]
    await checker.is_revoked(uuid.uuid4(), NOW, "j")
    clock = [time.monotonic()]
    monkeypatch.setattr(sr, "_clock", lambda: clock[0])

    caplog.clear()   # the failure that opened the window logged once; nothing more inside it
    with caplog.at_level(logging.WARNING, logger=sr._log.name):
        for _ in range(5):
            started = time.perf_counter()
            assert await checker.is_revoked(uuid.uuid4(), NOW, "j") == (False, sr.REASON_SKIPPED, None)
            assert time.perf_counter() - started < 0.05
    assert redis.calls == 1, "Redis not asked again inside the window"
    assert not [r for r in caplog.records if r.getMessage() == "session_revocation_check_unavailable"]

    clock[0] += 11
    await checker.is_revoked(uuid.uuid4(), NOW, "j")
    assert redis.calls == 2, "asked again once the window is over"


async def test_breaker_zero_turns_the_pause_off(monkeypatch) -> None:
    monkeypatch.setenv("SESSION_REVOCATION_BREAKER_SECONDS", "0")
    redis = _Hung(True)
    checker = sr._Checker(redis, mode="warn")  # type: ignore[arg-type]
    await checker.is_revoked(uuid.uuid4(), NOW, "j")
    await checker.is_revoked(uuid.uuid4(), NOW, "j")
    assert redis.calls == 2


async def test_one_mget_still_lets_an_exemption_win_over_a_marker() -> None:
    uid = uuid.uuid4()
    store = _Store({
        f"session_revoked_at:{uid}": (NOW + timedelta(minutes=1)).isoformat(),
        f"session_revoked_at:{uid}:exempt:j-ok": "1",
    })
    checker = sr._Checker(store, mode="enforce")  # type: ignore[arg-type]
    assert await checker.is_revoked(uid, NOW, "j-ok") == (False, None, None)
    revoked, reason, _ = await checker.is_revoked(uid, NOW, "j-other")
    assert revoked is True and reason is None
    assert store.mget_calls == 2, "one round trip per request"


async def test_while_skipping_fail_closed_still_refuses() -> None:
    from blumax_auth.context import AuthContext
    from blumax_auth.errors import InvalidToken

    checker = sr._Checker(_Hung(True), mode="enforce", fail_mode="closed")  # type: ignore[arg-type]
    sr._checker = checker
    try:
        ctx = AuthContext.__new__(AuthContext)
        object.__setattr__(ctx, "user_id", uuid.uuid4())
        object.__setattr__(ctx, "issued_at", NOW)
        object.__setattr__(ctx, "jti", "j")
        for _ in range(2):   # the failure itself, then a skipped request
            with pytest.raises(InvalidToken):
                await sr.check_session_revocation(ctx)
    finally:
        sr._checker = None
