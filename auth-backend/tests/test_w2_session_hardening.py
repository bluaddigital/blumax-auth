"""Wave 2: refresh consults the Redis session marker; user.password_changed sync ends the user's sessions; a Redis
failure AFTER the database commit is logged, never a 500 (the database rows are authoritative)."""
from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from httpx import AsyncClient
from redis.asyncio import Redis
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_redis
from app.core.config import settings
from app.main import app
from app.models.refresh_token import RefreshToken
from app.models.user import User

PASSWORD = "correct-horse-battery-staple"
NEW_PASSWORD = "a-new-strong-password-1"
_SYNC = {"X-Blumax-Auth-User-Sync-Key": settings.CORE_USER_SYNC_SERVICE_KEY}


async def _login(client: AsyncClient) -> tuple[str, str]:
    r = await client.post("/auth/login", json={"identifier": "alice@example.test", "password": PASSWORD})
    assert r.status_code == 200
    return r.json()["access_token"], r.json()["refresh_token"]


async def _live(db: AsyncSession, user_id: uuid.UUID) -> list[RefreshToken]:
    rows = await db.execute(
        select(RefreshToken).where(RefreshToken.user_id == user_id, RefreshToken.revoked.is_(False))
        .execution_options(populate_existing=True)
    )
    return list(rows.scalars())


def _write_marker(redis: Redis, user_id: uuid.UUID, at: datetime):
    return redis.set(f"session_revoked_at:{user_id}", at.isoformat(), ex=3600)


class _WriteFailingRedis:
    """Delegates to the real client; only the session-marker write fails (reset codes / rate limits still work)."""

    def __init__(self, inner: Redis) -> None:
        self._inner = inner

    async def set(self, key, *a, **kw):
        if str(key).startswith("session_revoked_at:"):
            raise ConnectionError("redis went away after the commit")
        return await self._inner.set(key, *a, **kw)

    def __getattr__(self, name):
        return getattr(self._inner, name)


@pytest.fixture
def failing_marker_writes(_fresh_redis_per_test: Redis):
    app.dependency_overrides[get_redis] = lambda: _WriteFailingRedis(_fresh_redis_per_test)
    yield
    app.dependency_overrides[get_redis] = lambda: _fresh_redis_per_test


# ─── refresh consults the marker ─────────────────────────────────────────────

async def test_refresh_is_refused_after_a_marker_newer_than_the_session(
    client: AsyncClient, test_user: User, _fresh_redis_per_test: Redis,
):
    _, refresh = await _login(client)
    await _write_marker(_fresh_redis_per_test, test_user.id, datetime.now(UTC) + timedelta(seconds=5))  # Core's force_login/logout
    r = await client.post("/auth/refresh", json={"refresh_token": refresh})
    assert r.status_code == 401 and "revoked" in r.text


async def test_refresh_still_works_when_the_marker_is_older_than_the_session(
    client: AsyncClient, test_user: User, _fresh_redis_per_test: Redis,
):
    await _write_marker(_fresh_redis_per_test, test_user.id, datetime.now(UTC) - timedelta(hours=1))
    _, refresh = await _login(client)
    assert (await client.post("/auth/refresh", json={"refresh_token": refresh})).status_code == 200


async def test_refresh_fails_closed_when_redis_is_down_in_closed_mode(
    client: AsyncClient, test_user: User, monkeypatch,
):
    _, refresh = await _login(client)

    class Down:
        async def get(self, *_a, **_k):
            raise ConnectionError("down")

    app.dependency_overrides[get_redis] = lambda: Down()
    monkeypatch.setattr(settings, "SESSION_REVOCATION_FAIL_MODE", "closed")
    r = await client.post("/auth/refresh", json={"refresh_token": refresh})
    assert r.status_code == 401


async def test_refresh_follows_open_mode_when_redis_is_down(client: AsyncClient, test_user: User, monkeypatch):
    _, refresh = await _login(client)

    class Down:
        async def get(self, *_a, **_k):
            raise ConnectionError("down")

    app.dependency_overrides[get_redis] = lambda: Down()
    monkeypatch.setattr(settings, "SESSION_REVOCATION_FAIL_MODE", "open")
    assert (await client.post("/auth/refresh", json={"refresh_token": refresh})).status_code == 200


# ─── user.password_changed sync ──────────────────────────────────────────────

async def _sync(client: AsyncClient, user: User, **fields):
    body = {"user_id": str(user.id), "hashed_password": user.hashed_password, **fields}
    return await client.post("/internal/users/sync", json=body, headers=_SYNC)


async def test_bare_password_changed_event_revokes_rows_and_writes_the_marker(
    client: AsyncClient, db_session: AsyncSession, test_user: User, _fresh_redis_per_test: Redis,
):
    _, refresh = await _login(client)
    await _login(client)
    assert (await _sync(client, test_user)).status_code == 204  # exactly Core's event shape: user_id + hashed_password
    assert await _live(db_session, test_user.id) == []
    assert await _fresh_redis_per_test.get(f"session_revoked_at:{test_user.id}")
    assert (await client.post("/auth/refresh", json={"refresh_token": refresh})).status_code == 401


async def test_a_changed_hash_on_any_event_shape_ends_the_sessions(
    client: AsyncClient, db_session: AsyncSession, test_user: User, _fresh_redis_per_test: Redis,
):
    from app.core.security import hash_password

    await _login(client)
    r = await client.post(
        "/internal/users/sync",
        json={"user_id": str(test_user.id), "hashed_password": hash_password(NEW_PASSWORD),
              "identifier": "alice@example.test", "username": "alice", "is_active": True},
        headers=_SYNC,
    )
    assert r.status_code == 204
    assert await _live(db_session, test_user.id) == []
    assert await _fresh_redis_per_test.get(f"session_revoked_at:{test_user.id}")


async def test_password_changed_retry_repairs_a_missing_marker(
    client: AsyncClient, test_user: User, _fresh_redis_per_test: Redis,
):
    await _login(client)
    assert (await _sync(client, test_user)).status_code == 204
    await _fresh_redis_per_test.delete(f"session_revoked_at:{test_user.id}")
    assert (await _sync(client, test_user)).status_code == 204
    assert await _fresh_redis_per_test.get(f"session_revoked_at:{test_user.id}")


async def test_password_changed_for_an_unknown_user_is_still_a_noop(client: AsyncClient, _fresh_redis_per_test: Redis):
    ghost = uuid.uuid4()
    r = await client.post(
        "/internal/users/sync", json={"user_id": str(ghost), "hashed_password": "x"}, headers=_SYNC,
    )
    assert r.status_code == 204
    assert await _fresh_redis_per_test.get(f"session_revoked_at:{ghost}") is None


# ─── Redis failure after the DB commit is not a 500 ──────────────────────────

async def test_change_password_survives_a_marker_write_failure(
    client: AsyncClient, db_session: AsyncSession, test_user: User, failing_marker_writes,
):
    access, refresh = await _login(client)
    r = await client.post(
        "/auth/change-password", json={"current_password": PASSWORD, "new_password": NEW_PASSWORD},
        headers={"Authorization": f"Bearer {access}"},
    )
    assert r.status_code == 204
    assert await _live(db_session, test_user.id) == []  # the database is authoritative
    assert (await client.post("/auth/refresh", json={"refresh_token": refresh})).status_code == 401


async def test_password_reset_confirm_survives_a_marker_write_failure(
    client: AsyncClient, db_session: AsyncSession, test_user: User, failing_marker_writes,
):
    _, refresh = await _login(client)
    req = await client.post(
        "/auth/password-reset/request", json={"identifier": "alice@example.test"},
        headers={"X-Dev-Tooling-Reveal-Key": settings.DEV_TOOLING_RESET_CODE_REVEAL_KEY},
    )
    code = req.json()["dev_reset_code"]
    r = await client.post("/auth/password-reset/confirm", json={"reset_code": code, "new_password": NEW_PASSWORD})
    assert r.status_code == 204
    assert await _live(db_session, test_user.id) == []


async def test_logout_all_devices_survives_a_marker_write_failure(
    client: AsyncClient, db_session: AsyncSession, test_user: User, failing_marker_writes,
):
    _, refresh = await _login(client)
    r = await client.post("/auth/logout", json={"refresh_token": refresh, "all_devices": True})
    assert r.status_code == 204
    assert await _live(db_session, test_user.id) == []


async def test_user_sync_deactivation_survives_a_marker_write_failure(
    client: AsyncClient, db_session: AsyncSession, test_user: User, failing_marker_writes,
):
    await _login(client)
    assert (await _sync(client, test_user, is_active=False)).status_code == 204
    assert await _live(db_session, test_user.id) == []


async def test_revoke_user_sessions_logs_and_returns_false_on_failure(caplog):
    from app.core.session_revocation import revoke_user_sessions

    class Boom:
        async def set(self, *a, **k):
            raise ConnectionError("x")

    assert await revoke_user_sessions(Boom(), "u1") is False  # type: ignore[arg-type]
