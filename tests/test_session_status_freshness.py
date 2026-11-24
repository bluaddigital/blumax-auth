"""Owner rule: an ordinary read relies on a session status at most 5 s old; sensitive operations never use the cache;
a session already seen revoked is never restored by cache expiry or a store outage."""
import logging
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from test_session_revocation_split_and_cache import (  # noqa: F401  (fixtures + helpers)
    LOGGER,
    FakeRedis,
    _env,
    auth,
    build_app,
    clock,
    make_client,
    redis,
    signer,
)

import blumax_auth.session_revocation as sr


def _future() -> datetime:
    return datetime.now(UTC) + timedelta(seconds=30)


@pytest.mark.parametrize("configured,expected", [(0, 0.0), (-1, 0.0), (3, 3.0), (5, 5.0), (5.01, 5.0), (3600, 5.0)])
def test_cache_seconds_are_clamped_to_five(configured, expected, caplog):
    with caplog.at_level(logging.WARNING, logger=LOGGER):
        assert sr.clamp_cache_seconds(configured) == expected
    clamped = [r for r in caplog.records if r.message == "session_status_cache_seconds_clamped"]
    assert bool(clamped) == (configured > 5)


def test_env_value_above_five_is_clamped_with_a_warning(monkeypatch, caplog, redis):
    monkeypatch.setenv(sr.CACHE_SECONDS_ENV, "60")
    with caplog.at_level(logging.WARNING, logger=LOGGER):
        checker = sr._Checker(redis, mode="enforce", cache_seconds=sr._cache_seconds_from_env())
    assert checker.cache_seconds == 5.0
    assert any(r.message == "session_status_cache_seconds_clamped" for r in caplog.records)


def test_recommended_default_is_three():
    assert sr.RECOMMENDED_CACHE_SECONDS == 3.0 and sr.MAX_CACHE_SECONDS == 5.0


async def test_revocation_is_visible_within_the_clamped_ttl_under_continuous_traffic(make_client, signer, redis, clock):
    client = make_client(cache_seconds=3600)  # configured absurdly high: clamped to 5
    assert sr._checker.cache_seconds == 5.0
    uid = uuid.uuid4()
    h = auth(signer, uid)
    assert (await client.get("/r", headers=h)).status_code == 200
    redis.revoke(uid, _future())  # written to the store now
    seen_at = None
    for step in range(100):  # a request every 0.1 s, never idle
        clock.now += 0.1
        if (await client.get("/r", headers=h)).status_code == 401:
            seen_at = step * 0.1
            break
    assert seen_at is not None and seen_at <= 5.0, seen_at  # hits do not extend an entry's life


async def test_cached_revoked_survives_a_store_outage_in_every_fail_mode(make_client, signer, redis, clock):
    for fail_mode in ("open", "closed", "split"):
        client = make_client(cache_seconds=3, fail_mode=fail_mode)
        uid = uuid.uuid4()
        h = auth(signer, uid)
        redis.fail = False
        redis.revoke(uid, _future())
        assert (await client.get("/r", headers=h)).status_code == 401
        redis.fail = True
        clock.now += 10_000  # far past any valid-answer TTL
        for method in ("get", "post"):
            assert (await getattr(client, method)("/r", headers=h)).status_code == 401, (fail_mode, method)
        assert (await client.get("/export", headers=h)).status_code == 401, fail_mode


async def test_known_revoked_is_not_restored_by_outage_even_with_cache_off(make_client, signer, redis, clock):
    client = make_client(fail_mode="open")  # no cache: exact old behaviour for everything else
    uid = uuid.uuid4()
    h = auth(signer, uid)
    redis.revoke(uid, _future())
    assert (await client.get("/r", headers=h)).status_code == 401
    redis.fail = True
    assert (await client.get("/r", headers=h)).status_code == 401
    other = auth(signer)  # a session never seen revoked keeps the configured open behaviour
    assert (await client.get("/r", headers=other)).status_code == 200


async def test_sensitive_never_uses_the_cache_and_fails_closed_when_fresh_status_is_unavailable(
    make_client, signer, redis, clock
):
    client = make_client(cache_seconds=3, fail_mode="split")
    h = auth(signer)
    assert (await client.get("/export", headers=h)).status_code == 200
    assert (await client.get("/r", headers=h)).status_code == 200   # now cached valid
    redis.fail = True
    assert (await client.get("/r", headers=h)).status_code == 200   # ordinary read: cached, within TTL
    assert (await client.get("/export", headers=h)).status_code == 503  # sensitive: cache ignored, fails closed
