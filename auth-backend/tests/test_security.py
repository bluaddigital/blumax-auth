from __future__ import annotations

import time

from httpx import AsyncClient

from app.core.security import hash_password, verify_password_constant_time


def test_constant_time_check_never_matches_dummy_hash():
    assert verify_password_constant_time("anything", None) is False


def test_constant_time_check_matches_real_password():
    hashed = hash_password("s3cret")
    assert verify_password_constant_time("s3cret", hashed) is True
    assert verify_password_constant_time("wrong", hashed) is False


def test_nonexistent_and_real_user_password_check_cost_is_comparable():
    """Not a precise timing-attack proof (too environment-sensitive for a
    unit test), but a sanity check that the nonexistent-user path pays a
    real bcrypt cost rather than returning near-instantly -- the bug the
    prior Core audit found was a >100x speed difference (skipped bcrypt
    entirely), not a few-percent variance."""
    hashed = hash_password("s3cret")

    t0 = time.perf_counter()
    verify_password_constant_time("guess", hashed)
    with_real_user = time.perf_counter() - t0

    t0 = time.perf_counter()
    verify_password_constant_time("guess", None)
    with_no_user = time.perf_counter() - t0

    # Both should be dominated by one bcrypt round -- same order of
    # magnitude, not one near-zero and one real.
    assert with_no_user > with_real_user * 0.3


async def test_login_rate_limited_after_repeated_attempts(client: AsyncClient, test_user):
    from app.core.config import settings

    responses = []
    for _ in range(settings.LOGIN_RATE_LIMIT_MAX_ATTEMPTS + 3):
        r = await client.post(
            "/auth/login", json={"identifier": "alice@example.test", "password": "wrong"}
        )
        responses.append(r.status_code)

    assert 429 in responses


async def test_no_secret_values_in_response_bodies_on_failure(client: AsyncClient, test_user):
    r = await client.post("/auth/login", json={"identifier": "alice@example.test", "password": "wrong"})
    body = r.text
    assert "hashed_password" not in body
    assert "$2b$" not in body  # bcrypt hash prefix never echoed back
