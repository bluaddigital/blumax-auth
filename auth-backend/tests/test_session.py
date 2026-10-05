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


async def test_me_includes_the_login_identifier(client: AsyncClient, test_user: User):
    """Phase 4I-1 (Superadmin frontend integration): added purely for a
    caller to display something human-readable -- never used by this
    service's own verification, which still reads only `sub`."""
    login = await client.post(
        "/auth/login", json={"identifier": "alice@example.test", "password": "correct-horse-battery-staple"}
    )
    access = login.json()["access_token"]
    r = await client.get("/auth/me", headers={"Authorization": f"Bearer {access}"})
    assert r.status_code == 200
    assert r.json()["identifier"] == "alice@example.test"


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


async def test_revocation_marker_is_written_as_an_iso_timestamp_on_the_wire(
    client: AsyncClient, test_user: User, _fresh_redis_per_test
):
    """Phase 4I-5B regression guard: the marker's KEY format
    (session_revoked_at:{user_id}) already matched the shared
    blumax_auth.session_revocation library's expectation, but the VALUE
    was a raw str(time.time()) epoch float -- the library's own read side
    does datetime.fromisoformat(raw), which raised on that shape and was
    silently caught as "marker_malformed", failing OPEN for every
    external consumer (found live, wiring this up for Superadmin). This
    pins the wire format directly so a future change can't silently
    regress it without this repo's own test suite catching it, even
    though no external consumer's code lives here to exercise."""
    login = await client.post(
        "/auth/login", json={"identifier": "alice@example.test", "password": "correct-horse-battery-staple"}
    )
    refresh = login.json()["refresh_token"]

    await client.post("/auth/logout", json={"refresh_token": refresh})

    marker = await _fresh_redis_per_test.get(f"session_revoked_at:{test_user.id}")
    assert marker is not None
    from datetime import datetime  # noqa: PLC0415

    datetime.fromisoformat(marker)  # raises ValueError if this regresses
