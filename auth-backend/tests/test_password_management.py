from __future__ import annotations

import asyncio

from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.security import verify_password_constant_time
from app.models.user import User


async def _login(client: AsyncClient, password: str = "correct-horse-battery-staple") -> tuple[str, str]:
    r = await client.post("/auth/login", json={"identifier": "alice@example.test", "password": password})
    assert r.status_code == 200
    return r.json()["access_token"], r.json()["refresh_token"]


# ─── Change password ────────────────────────────────────────────────────────

async def test_change_password_valid(client: AsyncClient, test_user: User, db_session: AsyncSession):
    access_token, _ = await _login(client)
    r = await client.post(
        "/auth/change-password",
        json={"current_password": "correct-horse-battery-staple", "new_password": "a-new-strong-password-1"},
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert r.status_code == 204

    await db_session.refresh(test_user)
    assert verify_password_constant_time("a-new-strong-password-1", test_user.hashed_password)
    assert not verify_password_constant_time("correct-horse-battery-staple", test_user.hashed_password)


async def test_change_password_wrong_current_rejected(client: AsyncClient, test_user: User):
    access_token, _ = await _login(client)
    r = await client.post(
        "/auth/change-password",
        json={"current_password": "totally-wrong", "new_password": "a-new-strong-password-1"},
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert r.status_code == 400


async def test_change_password_too_short_rejected(client: AsyncClient, test_user: User):
    access_token, _ = await _login(client)
    r = await client.post(
        "/auth/change-password",
        json={"current_password": "correct-horse-battery-staple", "new_password": "short"},
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert r.status_code == 400


async def test_change_password_revokes_existing_sessions(client: AsyncClient, test_user: User):
    """The access token used to MAKE the change-password call itself
    becomes invalid afterward -- every session is revoked, including the
    caller's own, matching the documented "no exemption, just revoke
    everything" design (see app/services/password_service.py)."""
    access_token, _ = await _login(client)
    r = await client.post(
        "/auth/change-password",
        json={"current_password": "correct-horse-battery-staple", "new_password": "a-new-strong-password-1"},
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert r.status_code == 204

    r2 = await client.get("/auth/me", headers={"Authorization": f"Bearer {access_token}"})
    assert r2.status_code == 401


# ─── Forgot / reset password ────────────────────────────────────────────────

async def test_reset_request_and_confirm(client: AsyncClient, test_user: User, db_session: AsyncSession):
    r1 = await client.post("/auth/password-reset/request", json={"identifier": "alice@example.test"})
    assert r1.status_code == 202
    code = r1.json()["dev_reset_code"]  # dev-mode-only convenience, see password_routes.py

    r2 = await client.post("/auth/password-reset/confirm", json={"reset_code": code, "new_password": "reset-password-123"})
    assert r2.status_code == 204

    await db_session.refresh(test_user)
    assert verify_password_constant_time("reset-password-123", test_user.hashed_password)


async def test_reset_request_for_unknown_identifier_same_response(client: AsyncClient):
    """Account-enumeration closed: an unknown identifier gets the exact
    same status code and body shape as a real one (modulo the dev-only
    code field being absent)."""
    r = await client.post("/auth/password-reset/request", json={"identifier": "nobody@example.test"})
    assert r.status_code == 202
    assert "dev_reset_code" not in r.json()
    assert r.json()["detail"] == "If the identifier exists, a reset code has been issued."


async def test_expired_reset_code_rejected(client: AsyncClient, test_user: User):
    original_ttl = settings.PASSWORD_RESET_TTL_SECONDS
    settings.PASSWORD_RESET_TTL_SECONDS = 1
    try:
        r1 = await client.post("/auth/password-reset/request", json={"identifier": "alice@example.test"})
        code = r1.json()["dev_reset_code"]
        await asyncio.sleep(1.5)
        r2 = await client.post("/auth/password-reset/confirm", json={"reset_code": code, "new_password": "reset-password-123"})
        assert r2.status_code == 400
        assert r2.json()["detail"] == "Invalid or expired reset code"
    finally:
        settings.PASSWORD_RESET_TTL_SECONDS = original_ttl


async def test_reused_reset_code_rejected(client: AsyncClient, test_user: User):
    r1 = await client.post("/auth/password-reset/request", json={"identifier": "alice@example.test"})
    code = r1.json()["dev_reset_code"]
    r2 = await client.post("/auth/password-reset/confirm", json={"reset_code": code, "new_password": "reset-password-123"})
    assert r2.status_code == 204
    r3 = await client.post("/auth/password-reset/confirm", json={"reset_code": code, "new_password": "another-password-456"})
    assert r3.status_code == 400
    assert r3.json()["detail"] == "Invalid or expired reset code"


async def test_reset_for_inactive_account_is_a_noop(client: AsyncClient, test_user: User, db_session: AsyncSession):
    test_user.is_active = False
    db_session.add(test_user)
    await db_session.commit()

    r1 = await client.post("/auth/password-reset/request", json={"identifier": "alice@example.test"})
    assert r1.status_code == 202
    # No code issued for an inactive account -- same shape as "unknown identifier".
    assert "dev_reset_code" not in r1.json()


async def test_reset_confirm_too_short_password_rejected(client: AsyncClient, test_user: User):
    r1 = await client.post("/auth/password-reset/request", json={"identifier": "alice@example.test"})
    code = r1.json()["dev_reset_code"]
    r2 = await client.post("/auth/password-reset/confirm", json={"reset_code": code, "new_password": "short"})
    assert r2.status_code == 400


async def test_reset_request_rate_limited(client: AsyncClient, test_user: User):
    for _ in range(settings.LOGIN_RATE_LIMIT_MAX_ATTEMPTS):
        await client.post("/auth/password-reset/request", json={"identifier": "alice@example.test"})
    r = await client.post("/auth/password-reset/request", json={"identifier": "alice@example.test"})
    assert r.status_code == 429
