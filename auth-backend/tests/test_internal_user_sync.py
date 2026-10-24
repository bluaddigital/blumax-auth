from __future__ import annotations

import uuid

from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models.user import User

_HEADERS = {"X-Blumax-Auth-User-Sync-Key": settings.CORE_USER_SYNC_SERVICE_KEY}


async def test_wrong_key_is_rejected(client: AsyncClient):
    r = await client.post(
        "/internal/users/sync",
        json={"user_id": str(uuid.uuid4()), "identifier": "x@example.test", "hashed_password": "h"},
        headers={"X-Blumax-Auth-User-Sync-Key": "wrong"},
    )
    assert r.status_code == 401


async def test_missing_key_is_rejected(client: AsyncClient):
    r = await client.post(
        "/internal/users/sync",
        json={"user_id": str(uuid.uuid4()), "identifier": "x@example.test", "hashed_password": "h"},
    )
    assert r.status_code == 401


async def test_creates_a_new_user(client: AsyncClient, db_session: AsyncSession):
    user_id = uuid.uuid4()
    r = await client.post(
        "/internal/users/sync",
        json={
            "user_id": str(user_id), "identifier": "New.Person@Example.test",
            "username": "newperson", "hashed_password": "some-hash", "is_active": True,
        },
        headers=_HEADERS,
    )
    assert r.status_code == 204

    row = await db_session.get(User, user_id)
    assert row is not None
    assert row.identifier == "new.person@example.test"  # normalized
    assert row.username == "newperson"
    assert row.hashed_password == "some-hash"
    assert row.is_active is True


async def test_password_changed_event_updates_only_the_hash(
    client: AsyncClient, test_user: User, db_session: AsyncSession
):
    r = await client.post(
        "/internal/users/sync",
        json={"user_id": str(test_user.id), "hashed_password": "new-hash-value"},
        headers=_HEADERS,
    )
    assert r.status_code == 204

    old_identifier, old_username = test_user.identifier, test_user.username
    await db_session.refresh(test_user)
    assert test_user.hashed_password == "new-hash-value"
    assert test_user.identifier == old_identifier  # untouched
    assert test_user.username == old_username  # untouched


async def test_password_changed_for_an_unknown_user_is_a_harmless_noop(client: AsyncClient):
    r = await client.post(
        "/internal/users/sync",
        json={"user_id": str(uuid.uuid4()), "hashed_password": "whatever"},
        headers=_HEADERS,
    )
    assert r.status_code == 204


async def test_identifier_conflict_with_a_different_user_is_409(
    client: AsyncClient, test_user: User, db_session: AsyncSession
):
    other_id = uuid.uuid4()
    other = User(id=other_id, identifier="someone-else@example.test", hashed_password="h", is_active=True)
    db_session.add(other)
    await db_session.commit()

    r = await client.post(
        "/internal/users/sync",
        json={
            "user_id": str(other_id), "identifier": test_user.identifier,
            "hashed_password": "h2", "is_active": True,
        },
        headers=_HEADERS,
    )
    assert r.status_code == 409


async def test_resync_of_an_existing_user_is_idempotent(
    client: AsyncClient, test_user: User, db_session: AsyncSession
):
    r = await client.post(
        "/internal/users/sync",
        json={
            "user_id": str(test_user.id), "identifier": test_user.identifier,
            "username": test_user.username, "hashed_password": test_user.hashed_password,
            "is_active": True,
        },
        headers=_HEADERS,
    )
    assert r.status_code == 204

    count = (
        await db_session.execute(select(User).where(User.id == test_user.id))
    ).scalars().all()
    assert len(count) == 1
