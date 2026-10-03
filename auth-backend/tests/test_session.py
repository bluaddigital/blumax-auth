from __future__ import annotations

from httpx import AsyncClient

from app.models.user import User


async def test_login_then_me_succeeds(client: AsyncClient, test_user: User):
    login = await client.post(
        "/auth/login", json={"identifier": "alice@example.test", "password": "correct-horse-battery-staple"}
    )
    access = login.json()["access_token"]
    r = await client.get("/auth/me", headers={"Authorization": f"Bearer {access}"})
    assert r.status_code == 200
    assert r.json()["sub"] == str(test_user.id)


async def test_logout_revokes_refresh_token(client: AsyncClient, test_user: User):
    login = await client.post(
        "/auth/login", json={"identifier": "alice@example.test", "password": "correct-horse-battery-staple"}
    )
    refresh = login.json()["refresh_token"]

    logout = await client.post("/auth/logout", json={"refresh_token": refresh})
    assert logout.status_code == 204

    r = await client.post("/auth/refresh", json={"refresh_token": refresh})
    assert r.status_code == 401


async def test_logout_revokes_still_unexpired_access_token(client: AsyncClient, test_user: User):
    """The whole point of the Redis session-revocation marker: an access
    token that hasn't naturally expired yet must stop being honoured the
    moment its owner logs out."""
    login = await client.post(
        "/auth/login", json={"identifier": "alice@example.test", "password": "correct-horse-battery-staple"}
    )
    access = login.json()["access_token"]
    refresh = login.json()["refresh_token"]

    me_before = await client.get("/auth/me", headers={"Authorization": f"Bearer {access}"})
    assert me_before.status_code == 200

    await client.post("/auth/logout", json={"refresh_token": refresh})

    me_after = await client.get("/auth/me", headers={"Authorization": f"Bearer {access}"})
    assert me_after.status_code == 401


async def test_missing_bearer_rejected(client: AsyncClient):
    r = await client.get("/auth/me")
    assert r.status_code == 401
