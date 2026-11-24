"""Phase 5b: per-session (`sid`) revocation marker, `session_revoked_sid:{sid}`.

Core writes the marker (SSO_SID_REVOCATION=on) when ONE refresh family is logged out; SSO child sessions share the
family's sid, so their access tokens end at once. The library reads it in the SAME MGET as the per-user keys, and only
when the token carries a sid: a no-sid token reads exactly the keys it read before, and an absent marker changes nothing.
"""
from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest

import blumax_auth.session_revocation as sr
from blumax_auth.errors import InvalidToken, SessionRevocationUnavailable
from blumax_auth.verify import _to_context


class FakeRedis:
    def __init__(self) -> None:
        self.store: dict[str, str] = {}
        self.fail: Exception | None = None
        self.mget_calls: list[list[str]] = []

    async def mget(self, keys):
        self.mget_calls.append(list(keys))
        if self.fail is not None:
            raise self.fail
        return [self.store.get(k) for k in keys]

    async def get(self, key):  # pragma: no cover - must never be used when mget exists
        raise AssertionError("second round trip")


class Req:
    def __init__(self, method: str = "GET") -> None:
        self.method = method

        class _S:  # noqa: N801
            pass

        self.state = _S()


USER = uuid.uuid4()
SID = uuid.uuid4()


def _ctx(*, sid: uuid.UUID | None = SID, iat: datetime | None = None, jti: str | None = "j1"):
    claims = {"sub": str(USER), "jti": jti, "iat": int((iat or datetime.now(UTC) - timedelta(minutes=5)).timestamp())}
    if sid is not None:
        claims["sid"] = str(sid)
    return _to_context(claims, is_service=False)


@pytest.fixture
def redis():
    r = FakeRedis()
    yield r
    sr.reset_session_revocation()


def _configure(redis: FakeRedis, **kw) -> None:
    sr._checker = sr._Checker(redis, mode=kw.pop("mode", "enforce"), **kw)  # type: ignore[arg-type]


def test_context_carries_sid_and_ignores_a_malformed_one():
    assert _ctx().session_id == SID
    assert _ctx(sid=None).session_id is None
    bad = _to_context({"sub": str(USER), "sid": "not-a-uuid", "iat": 1}, is_service=False)
    assert bad.session_id is None  # never a verification failure


async def test_sid_marker_revokes_in_one_round_trip(redis):
    _configure(redis)
    redis.store[f"session_revoked_sid:{SID}"] = datetime.now(UTC).isoformat()
    with pytest.raises(InvalidToken):
        await sr._check(_ctx(), Req(), sensitive=False)
    assert len(redis.mget_calls) == 1
    assert redis.mget_calls[0] == [f"session_revoked_at:{USER}:exempt:j1", f"session_revoked_at:{USER}",
                                   f"session_revoked_sid:{SID}"]


async def test_absent_sid_marker_is_a_no_op(redis):
    _configure(redis)
    await sr._check(_ctx(), Req(), sensitive=False)
    assert len(redis.mget_calls) == 1


async def test_token_without_sid_reads_the_old_keys_only(redis):
    _configure(redis)
    redis.store[f"session_revoked_sid:{SID}"] = datetime.now(UTC).isoformat()
    await sr._check(_ctx(sid=None), Req(), sensitive=False)
    assert redis.mget_calls == [[f"session_revoked_at:{USER}:exempt:j1", f"session_revoked_at:{USER}"]]


async def test_other_sid_not_affected(redis):
    _configure(redis)
    redis.store[f"session_revoked_sid:{uuid.uuid4()}"] = datetime.now(UTC).isoformat()
    await sr._check(_ctx(), Req(), sensitive=False)


async def test_token_issued_after_the_marker_passes(redis):
    _configure(redis)
    redis.store[f"session_revoked_sid:{SID}"] = (datetime.now(UTC) - timedelta(hours=1)).isoformat()
    await sr._check(_ctx(iat=datetime.now(UTC)), Req(), sensitive=False)


async def test_jti_exemption_does_not_spare_a_revoked_session(redis):
    _configure(redis)
    redis.store[f"session_revoked_at:{USER}:exempt:j1"] = "1"
    redis.store[f"session_revoked_sid:{SID}"] = datetime.now(UTC).isoformat()
    with pytest.raises(InvalidToken):
        await sr._check(_ctx(), Req(), sensitive=False)


async def test_user_marker_still_honoured_alongside_sid(redis):
    _configure(redis)
    redis.store[f"session_revoked_at:{USER}"] = datetime.now(UTC).isoformat()
    with pytest.raises(InvalidToken):
        await sr._check(_ctx(), Req(), sensitive=False)


async def test_warn_mode_never_rejects(redis):
    _configure(redis, mode="warn")
    redis.store[f"session_revoked_sid:{SID}"] = datetime.now(UTC).isoformat()
    await sr._check(_ctx(), Req(), sensitive=False)


async def test_malformed_sid_marker_follows_fail_mode(redis):
    redis.store[f"session_revoked_sid:{SID}"] = "garbage"
    _configure(redis, fail_mode="open")
    await sr._check(_ctx(), Req(), sensitive=False)  # open: passes (logged)
    _configure(redis, fail_mode="closed")
    with pytest.raises(InvalidToken):
        await sr._check(_ctx(), Req(), sensitive=False)


async def test_store_unavailable_same_fail_modes(redis):
    redis.fail = ConnectionError("down")
    _configure(redis, fail_mode="open")
    await sr._check(_ctx(), Req(), sensitive=False)
    _configure(redis, fail_mode="closed")
    with pytest.raises(InvalidToken):
        await sr._check(_ctx(), Req(), sensitive=False)
    _configure(redis, fail_mode="split")
    with pytest.raises(SessionRevocationUnavailable):
        await sr._check(_ctx(), Req("POST"), sensitive=False)


async def test_status_cache_remembers_sid_revocation(redis):
    _configure(redis, cache_seconds=3)
    redis.store[f"session_revoked_sid:{SID}"] = datetime.now(UTC).isoformat()
    ctx = _ctx()
    with pytest.raises(InvalidToken):
        await sr._check(ctx, Req(), sensitive=False)
    redis.fail = ConnectionError("down")  # a session seen revoked stays revoked through an outage
    with pytest.raises(InvalidToken):
        await sr._check(ctx, Req(), sensitive=False)
