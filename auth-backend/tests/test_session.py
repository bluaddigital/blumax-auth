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


async def test_ordinary_logout_does_not_revoke_other_sessions(client: AsyncClient, test_user: User):
    """An ordinary (all_devices=False) logout must only end the session doing
    the logging out, never every other concurrent session for that account —
    concurrent logins are intended platform behavior (confirmed 2026-09-23).

    The Redis revocation marker is per-USER, not per-session, so there is no
    way to narrowly kill only the logging-out session's own access token
    without also killing every other one; revoke_user_sessions is therefore
    called ONLY for an explicit all_devices logout. An ordinary logout's own
    access token is left to expire on its own schedule, same as before this
    revocation mechanism existed -- this is the accepted trade-off for not
    silently ending other devices' sessions (found live: a shared/test
    account used from multiple places at once was being logged out of
    unexpectedly every time any one of those sessions logged out normally)."""
    session_a = await client.post(
        "/auth/login", json={"identifier": "alice@example.test", "password": "correct-horse-battery-staple"}
    )
    session_b = await client.post(
        "/auth/login", json={"identifier": "alice@example.test", "password": "correct-horse-battery-staple"}
    )
    access_b = session_b.json()["access_token"]
    refresh_a = session_a.json()["refresh_token"]

    await client.post("/auth/logout", json={"refresh_token": refresh_a})

    me_b = await client.get("/auth/me", headers={"Authorization": f"Bearer {access_b}"})
    assert me_b.status_code == 200


async def test_all_devices_logout_revokes_every_session(client: AsyncClient, test_user: User):
    session_a = await client.post(
        "/auth/login", json={"identifier": "alice@example.test", "password": "correct-horse-battery-staple"}
    )
    session_b = await client.post(
        "/auth/login", json={"identifier": "alice@example.test", "password": "correct-horse-battery-staple"}
    )
    access_b = session_b.json()["access_token"]
    refresh_a = session_a.json()["refresh_token"]

    await client.post("/auth/logout", json={"refresh_token": refresh_a, "all_devices": True})

    me_b = await client.get("/auth/me", headers={"Authorization": f"Bearer {access_b}"})
    assert me_b.status_code == 401


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

    # all_devices=True: an ordinary logout no longer writes this marker at
    # all (see test_ordinary_logout_does_not_revoke_other_sessions).
    await client.post("/auth/logout", json={"refresh_token": refresh, "all_devices": True})

    marker = await _fresh_redis_per_test.get(f"session_revoked_at:{test_user.id}")
    assert marker is not None
    from datetime import datetime  # noqa: PLC0415

    datetime.fromisoformat(marker)  # raises ValueError if this regresses
