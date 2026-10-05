from __future__ import annotations

from httpx import AsyncClient

from app.models.user import User


async def test_valid_login_returns_tokens(client: AsyncClient, test_user: User):
    r = await client.post(
        "/auth/login", json={"identifier": "alice@example.test", "password": "correct-horse-battery-staple"}
    )
    assert r.status_code == 200
    body = r.json()
    assert body["access_token"]
    assert body["refresh_token"]
    assert body["token_type"] == "bearer"


async def test_login_by_username_also_works(client: AsyncClient, test_user: User):
    # Mirrors Core's own email-OR-username login (see
    # migrations/versions/003_username.py) -- the same account, the same
    # password, reached through its username instead of its email.
    r = await client.post(
        "/auth/login", json={"identifier": "alice", "password": "correct-horse-battery-staple"}
    )
    assert r.status_code == 200
    assert r.json()["access_token"]


async def test_login_by_username_is_case_insensitive(client: AsyncClient, test_user: User):
    r = await client.post(
        "/auth/login", json={"identifier": "ALICE", "password": "correct-horse-battery-staple"}
    )
    assert r.status_code == 200


async def test_login_by_username_wrong_password_rejected(client: AsyncClient, test_user: User):
    r = await client.post("/auth/login", json={"identifier": "alice", "password": "wrong"})
    assert r.status_code == 401


async def test_invalid_password_rejected(client: AsyncClient, test_user: User):
    r = await client.post("/auth/login", json={"identifier": "alice@example.test", "password": "wrong"})
    assert r.status_code == 401


async def test_nonexistent_user_rejected_with_identical_message(client: AsyncClient, test_user: User):
    r_bad_user = await client.post("/auth/login", json={"identifier": "nobody@example.test", "password": "x"})
    r_bad_pass = await client.post("/auth/login", json={"identifier": "alice@example.test", "password": "x"})
    assert r_bad_user.status_code == r_bad_pass.status_code == 401
    assert r_bad_user.json()["detail"] == r_bad_pass.json()["detail"] == "Invalid credentials"


async def test_disabled_user_rejected(client: AsyncClient, db_session, test_user: User):
    test_user.is_active = False
    db_session.add(test_user)
    await db_session.commit()
    r = await client.post(
        "/auth/login", json={"identifier": "alice@example.test", "password": "correct-horse-battery-staple"}
    )
    assert r.status_code == 401
    assert r.json()["detail"] == "Account is deactivated"
