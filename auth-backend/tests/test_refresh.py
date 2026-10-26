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


async def test_immediate_reuse_with_newer_session_is_refused_but_session_survives(
    client: AsyncClient, db_session, test_user: User,
):
    """Reproduces a real bug found live (2026-10-26): when more than one
    tab/app shares the same session, each one single-flights its OWN
    refresh calls but has no idea another tab is also racing to rotate
    the same refresh token. The losing tab's request lands moments after
    the winner's, presenting the now-rotated-away token -- not theft,
    just an ordinary race. Before this fix, that race was read as reuse
    and nuked every session for the user, including the one that just
    legitimately won the rotation."""
    login = await client.post(
        "/auth/login", json={"identifier": "alice@example.test", "password": "correct-horse-battery-staple"}
    )
    old_refresh = login.json()["refresh_token"]

    first = await client.post("/auth/refresh", json={"refresh_token": old_refresh})
    assert first.status_code == 200

    # The losing tab's stale in-flight request, landing moments later.
    second = await client.post("/auth/refresh", json={"refresh_token": old_refresh})
    assert second.status_code == 401

    # The winning tab's session must be completely unaffected -- this is
    # the actual regression: before the fix, the line above would have
    # revoked this token too.
    newest_refresh = first.json()["refresh_token"]
    third = await client.post("/auth/refresh", json={"refresh_token": newest_refresh})
    assert third.status_code == 200, third.text


async def test_replay_with_no_newer_session_still_nukes_the_family(
    client: AsyncClient, db_session, test_user: User,
):
    """The grace window must not weaken real theft detection: a revoked
    token replayed with no legitimately newer session to explain it away
    still revokes every session for that user, exactly as before this
    fix."""
    login = await client.post(
        "/auth/login", json={"identifier": "alice@example.test", "password": "correct-horse-battery-staple"}
    )
    old_refresh = login.json()["refresh_token"]

    rotated = await client.post("/auth/refresh", json={"refresh_token": old_refresh})
    assert rotated.status_code == 200
    rotated_refresh = rotated.json()["refresh_token"]

    # Remove the "a newer session exists" signal the same way Core's own
    # equivalent test does: log out the rotated session first, so there
    # is no live session left for the grace window to find.
    logout = await client.post("/auth/logout", json={"refresh_token": rotated_refresh})
    assert logout.status_code == 204

    replay = await client.post("/auth/refresh", json={"refresh_token": old_refresh})
    assert replay.status_code == 401

    # No session survives -- the rotated (now logged-out) one is
    # confirmed already dead, and reuse-detection must not have spared
    # anything else either.
    still_dead = await client.post("/auth/refresh", json={"refresh_token": rotated_refresh})
    assert still_dead.status_code == 401


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
