"""Phase 0 session-revocation fixes (JWT/SSO audit D-6, D-7).

D-6: refresh rejects an inactive user, ends that user's refresh family, and uses the configured lifetime.
D-7: password change / reset and user_sync deactivation revoke the refresh rows in the DATABASE and write the Redis
marker (a refresh token must not outlive a password reset; a deactivated account must not keep minting tokens).
"""
from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from httpx import AsyncClient
from redis.asyncio import Redis
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models.refresh_token import RefreshToken
from app.models.user import User

PASSWORD = "correct-horse-battery-staple"
_SYNC_HEADERS = {"X-Blumax-Auth-User-Sync-Key": settings.CORE_USER_SYNC_SERVICE_KEY}


async def _login(client: AsyncClient) -> tuple[str, str]:
    r = await client.post("/auth/login", json={"identifier": "alice@example.test", "password": PASSWORD})
    assert r.status_code == 200
    return r.json()["access_token"], r.json()["refresh_token"]


async def _live_rows(db: AsyncSession, user_id: uuid.UUID) -> list[RefreshToken]:
    rows = await db.execute(
        select(RefreshToken)
        .where(RefreshToken.user_id == user_id, RefreshToken.revoked.is_(False))
        .execution_options(populate_existing=True)
    )
    return list(rows.scalars())


async def _marker(redis: Redis, user_id: uuid.UUID) -> str | None:
    return await redis.get(f"session_revoked_at:{user_id}")


# ─── D-6: refresh ────────────────────────────────────────────────────────────

async def test_refresh_rejects_a_user_deactivated_after_login(
    client: AsyncClient, db_session: AsyncSession, test_user: User,
):
    _, refresh = await _login(client)
    test_user.is_active = False
    await db_session.commit()

    r = await client.post("/auth/refresh", json={"refresh_token": refresh})
    assert r.status_code == 401
    assert "deactivated" in r.text
    assert await _live_rows(db_session, test_user.id) == []  # the family is ended, not just this call refused


async def test_refresh_of_a_deactivated_user_ends_the_other_sessions_too(
    client: AsyncClient, db_session: AsyncSession, test_user: User,
):
    _, first = await _login(client)
    _, second = await _login(client)  # a second device
    test_user.is_active = False
    await db_session.commit()
    assert (await client.post("/auth/refresh", json={"refresh_token": first})).status_code == 401
    assert (await client.post("/auth/refresh", json={"refresh_token": second})).status_code == 401


async def test_refresh_for_an_active_user_still_works(client: AsyncClient, test_user: User):
    _, refresh = await _login(client)
    r = await client.post("/auth/refresh", json={"refresh_token": refresh})
    assert r.status_code == 200 and r.json()["refresh_token"] != refresh


async def test_refresh_uses_the_configured_lifetime_not_14_days(
    client: AsyncClient, db_session: AsyncSession, test_user: User, monkeypatch,
):
    monkeypatch.setattr(settings, "REFRESH_TOKEN_EXPIRE_DAYS", 3)
    _, refresh = await _login(client)
    assert (await client.post("/auth/refresh", json={"refresh_token": refresh})).status_code == 200
    rows = await _live_rows(db_session, test_user.id)
    assert rows, "the rotated row is live"
    for row in rows:
        remaining = row.expires_at - datetime.now(UTC)
        assert timedelta(days=2, hours=23) < remaining <= timedelta(days=3), remaining  # login row AND refreshed row


async def test_default_lifetime_is_unchanged_at_14_days(
    client: AsyncClient, db_session: AsyncSession, test_user: User,
):
    assert settings.REFRESH_TOKEN_EXPIRE_DAYS == 14
    _, refresh = await _login(client)
    await client.post("/auth/refresh", json={"refresh_token": refresh})
    for row in await _live_rows(db_session, test_user.id):
        assert timedelta(days=13, hours=23) < row.expires_at - datetime.now(UTC) <= timedelta(days=14)


# ─── D-7: password change / reset ────────────────────────────────────────────

async def test_change_password_revokes_refresh_rows_and_writes_the_marker(
    client: AsyncClient, db_session: AsyncSession, test_user: User, _fresh_redis_per_test: Redis,
):
    access, refresh = await _login(client)
    await _login(client)  # another device
    assert len(await _live_rows(db_session, test_user.id)) == 2

    r = await client.post(
        "/auth/change-password",
        json={"current_password": PASSWORD, "new_password": "a-new-strong-password-1"},
        headers={"Authorization": f"Bearer {access}"},
    )
    assert r.status_code == 204
    assert await _live_rows(db_session, test_user.id) == []
    assert await _marker(_fresh_redis_per_test, test_user.id) is not None
    # the thief's copy of the old refresh token is dead
    assert (await client.post("/auth/refresh", json={"refresh_token": refresh})).status_code == 401


async def test_password_reset_revokes_refresh_rows_and_writes_the_marker(
    client: AsyncClient, db_session: AsyncSession, test_user: User, _fresh_redis_per_test: Redis,
):
    _, refresh = await _login(client)
    req = await client.post(
        "/auth/password-reset/request", json={"identifier": "alice@example.test"},
        headers={"X-Dev-Tooling-Reveal-Key": settings.DEV_TOOLING_RESET_CODE_REVEAL_KEY},
    )
    code = req.json().get("dev_reset_code")
    assert code, req.text
    r = await client.post(
        "/auth/password-reset/confirm", json={"reset_code": code, "new_password": "a-new-strong-password-1"},
    )
    assert r.status_code == 204
    assert await _live_rows(db_session, test_user.id) == []
    assert await _marker(_fresh_redis_per_test, test_user.id) is not None
    assert (await client.post("/auth/refresh", json={"refresh_token": refresh})).status_code == 401


async def test_a_failed_change_password_revokes_nothing(
    client: AsyncClient, db_session: AsyncSession, test_user: User, _fresh_redis_per_test: Redis,
):
    access, _ = await _login(client)
    r = await client.post(
        "/auth/change-password",
        json={"current_password": "wrong", "new_password": "a-new-strong-password-1"},
        headers={"Authorization": f"Bearer {access}"},
    )
    assert r.status_code == 400
    assert len(await _live_rows(db_session, test_user.id)) == 1
    assert await _marker(_fresh_redis_per_test, test_user.id) is None


# ─── D-6: user_sync deactivation ─────────────────────────────────────────────

async def _sync(client: AsyncClient, user: User, **fields):
    return await client.post(
        "/internal/users/sync",
        json={"user_id": str(user.id), "hashed_password": user.hashed_password, **fields},
        headers=_SYNC_HEADERS,
    )


async def test_user_sync_deactivation_revokes_refresh_rows_and_writes_the_marker(
    client: AsyncClient, db_session: AsyncSession, test_user: User, _fresh_redis_per_test: Redis,
):
    _, refresh = await _login(client)
    r = await _sync(client, test_user, identifier="alice@example.test", username="alice", is_active=False)
    assert r.status_code == 204
    assert await _live_rows(db_session, test_user.id) == []
    assert await _marker(_fresh_redis_per_test, test_user.id) is not None
    assert (await client.post("/auth/refresh", json={"refresh_token": refresh})).status_code == 401


async def test_user_sync_deactivation_repairs_a_missing_marker_on_retry(
    client: AsyncClient, db_session: AsyncSession, test_user: User, _fresh_redis_per_test: Redis,
):
    await _login(client)
    assert (await _sync(client, test_user, is_active=False)).status_code == 204
    await _fresh_redis_per_test.delete(f"session_revoked_at:{test_user.id}")  # the marker write had failed
    assert (await _sync(client, test_user, is_active=False)).status_code == 204  # relay retry; user already inactive
    assert await _marker(_fresh_redis_per_test, test_user.id) is not None


async def test_user_sync_that_keeps_the_user_active_revokes_nothing(
    client: AsyncClient, db_session: AsyncSession, test_user: User, _fresh_redis_per_test: Redis,
):
    await _login(client)
    for fields in ({"is_active": True}, {"identifier": "alice@example.test", "username": "alice"}):  # unchanged password, still active
        assert (await _sync(client, test_user, **fields)).status_code == 204
    assert len(await _live_rows(db_session, test_user.id)) == 1
    assert await _marker(_fresh_redis_per_test, test_user.id) is None
