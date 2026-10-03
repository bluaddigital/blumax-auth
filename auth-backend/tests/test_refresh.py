from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from httpx import AsyncClient

from app.core.security import create_refresh_token
from app.models.refresh_token import RefreshToken
from app.models.user import User


async def test_valid_refresh_issues_new_pair(client: AsyncClient, test_user: User):
    login = await client.post(
        "/auth/login", json={"identifier": "alice@example.test", "password": "correct-horse-battery-staple"}
    )
    old_refresh = login.json()["refresh_token"]

    r = await client.post("/auth/refresh", json={"refresh_token": old_refresh})
    assert r.status_code == 200
    body = r.json()
    assert body["access_token"]
    assert body["refresh_token"] != old_refresh


async def test_expired_refresh_rejected(client: AsyncClient, db_session, test_user: User):
    row = RefreshToken(
        id=uuid.uuid4(), user_id=test_user.id,
        expires_at=datetime.now(UTC) - timedelta(days=1),
    )
    db_session.add(row)
    await db_session.commit()
    token = create_refresh_token(user_id=test_user.id, token_id=row.id)

    r = await client.post("/auth/refresh", json={"refresh_token": token})
    assert r.status_code == 401


async def test_revoked_refresh_rejected_and_detected_as_reuse(client: AsyncClient, db_session, test_user: User):
    login = await client.post(
        "/auth/login", json={"identifier": "alice@example.test", "password": "correct-horse-battery-staple"}
    )
    old_refresh = login.json()["refresh_token"]

    first = await client.post("/auth/refresh", json={"refresh_token": old_refresh})
    assert first.status_code == 200

    # Reusing the now-rotated-away token must be rejected...
    second = await client.post("/auth/refresh", json={"refresh_token": old_refresh})
    assert second.status_code == 401

    # ...and must have revoked the entire family, including the token
    # issued by the first (legitimate) refresh.
    newest_refresh = first.json()["refresh_token"]
    third = await client.post("/auth/refresh", json={"refresh_token": newest_refresh})
    assert third.status_code == 401


async def test_rotation_leaves_exactly_one_live_token_per_login(client: AsyncClient, db_session, test_user: User):
    from sqlalchemy import select
    login = await client.post(
        "/auth/login", json={"identifier": "alice@example.test", "password": "correct-horse-battery-staple"}
    )
    old_refresh = login.json()["refresh_token"]
    await client.post("/auth/refresh", json={"refresh_token": old_refresh})

    result = await db_session.execute(
        select(RefreshToken).where(RefreshToken.user_id == test_user.id, RefreshToken.revoked.is_(False))
    )
    live = result.scalars().all()
    assert len(live) == 1
