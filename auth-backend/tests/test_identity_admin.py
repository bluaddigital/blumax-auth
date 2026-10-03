from __future__ import annotations

import uuid

from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import verify_password_constant_time
from app.models.user import User


async def _service_token(client: AsyncClient, client_id: str, client_secret: str) -> str:
    r = await client.post("/auth/service-token", json={"client_id": client_id, "client_secret": client_secret})
    assert r.status_code == 200, r.text
    return r.json()["access_token"]


async def test_create_identity(client: AsyncClient, make_service_account, db_session: AsyncSession):
    account, secret = await make_service_account(may_manage_identities=True)
    svc_token = await _service_token(client, account.client_id, secret)

    r = await client.post(
        "/admin/identities", json={"identifier": "new-user@example.test", "password": "a-strong-password-1"},
        headers={"Authorization": f"Bearer {svc_token}"},
    )
    assert r.status_code == 201
    body = r.json()
    assert body["identifier"] == "new-user@example.test"
    assert body["is_active"] is True
    assert body["temporary_password"] is None

    row = (await db_session.execute(select(User).where(User.id == uuid.UUID(body["id"])))).scalar_one()
    assert verify_password_constant_time("a-strong-password-1", row.hashed_password)


async def test_create_identity_without_password_returns_temp_password(client: AsyncClient, make_service_account):
    account, secret = await make_service_account(may_manage_identities=True)
    svc_token = await _service_token(client, account.client_id, secret)
    r = await client.post(
        "/admin/identities", json={"identifier": "no-password-user@example.test"},
        headers={"Authorization": f"Bearer {svc_token}"},
    )
    assert r.status_code == 201
    assert r.json()["temporary_password"]


async def test_duplicate_identifier_rejected(client: AsyncClient, test_user: User, make_service_account):
    account, secret = await make_service_account(may_manage_identities=True)
    svc_token = await _service_token(client, account.client_id, secret)
    r = await client.post(
        "/admin/identities", json={"identifier": "alice@example.test", "password": "another-password-1"},
        headers={"Authorization": f"Bearer {svc_token}"},
    )
    assert r.status_code == 409


async def test_create_identity_without_scope_rejected(client: AsyncClient, make_service_account):
    account, secret = await make_service_account(may_manage_identities=False)
    svc_token = await _service_token(client, account.client_id, secret)
    r = await client.post(
        "/admin/identities", json={"identifier": "blocked@example.test", "password": "a-strong-password-1"},
        headers={"Authorization": f"Bearer {svc_token}"},
    )
    assert r.status_code == 403


async def test_get_identity(client: AsyncClient, test_user: User, make_service_account):
    account, secret = await make_service_account(may_manage_identities=True)
    svc_token = await _service_token(client, account.client_id, secret)
    r = await client.get(f"/admin/identities/{test_user.id}", headers={"Authorization": f"Bearer {svc_token}"})
    assert r.status_code == 200
    assert r.json()["identifier"] == "alice@example.test"


async def test_get_unknown_identity_404(client: AsyncClient, make_service_account):
    account, secret = await make_service_account(may_manage_identities=True)
    svc_token = await _service_token(client, account.client_id, secret)
    r = await client.get(f"/admin/identities/{uuid.uuid4()}", headers={"Authorization": f"Bearer {svc_token}"})
    assert r.status_code == 404


async def test_deactivate_then_login_fails(client: AsyncClient, test_user: User, make_service_account):
    account, secret = await make_service_account(may_manage_identities=True)
    svc_token = await _service_token(client, account.client_id, secret)
    r = await client.post(f"/admin/identities/{test_user.id}/deactivate", headers={"Authorization": f"Bearer {svc_token}"})
    assert r.status_code == 204

    r2 = await client.post(
        "/auth/login", json={"identifier": "alice@example.test", "password": "correct-horse-battery-staple"},
    )
    assert r2.status_code == 401
    assert r2.json()["detail"] == "Account is deactivated"


async def test_deactivate_revokes_existing_session_immediately(client: AsyncClient, test_user: User, make_service_account):
    r0 = await client.post(
        "/auth/login", json={"identifier": "alice@example.test", "password": "correct-horse-battery-staple"},
    )
    access_token = r0.json()["access_token"]

    account, secret = await make_service_account(may_manage_identities=True)
    svc_token = await _service_token(client, account.client_id, secret)
    await client.post(f"/admin/identities/{test_user.id}/deactivate", headers={"Authorization": f"Bearer {svc_token}"})

    r = await client.get("/auth/me", headers={"Authorization": f"Bearer {access_token}"})
    assert r.status_code == 401


async def test_activate_reverses_deactivation(client: AsyncClient, test_user: User, make_service_account):
    account, secret = await make_service_account(may_manage_identities=True)
    svc_token = await _service_token(client, account.client_id, secret)
    await client.post(f"/admin/identities/{test_user.id}/deactivate", headers={"Authorization": f"Bearer {svc_token}"})
    r = await client.post(f"/admin/identities/{test_user.id}/activate", headers={"Authorization": f"Bearer {svc_token}"})
    assert r.status_code == 204

    r2 = await client.post(
        "/auth/login", json={"identifier": "alice@example.test", "password": "correct-horse-battery-staple"},
    )
    assert r2.status_code == 200


async def test_admin_set_password(client: AsyncClient, test_user: User, make_service_account, db_session: AsyncSession):
    account, secret = await make_service_account(may_manage_identities=True)
    svc_token = await _service_token(client, account.client_id, secret)
    r = await client.post(
        f"/admin/identities/{test_user.id}/set-password", json={"new_password": "admin-set-password-1"},
        headers={"Authorization": f"Bearer {svc_token}"},
    )
    assert r.status_code == 204

    await db_session.refresh(test_user)
    assert verify_password_constant_time("admin-set-password-1", test_user.hashed_password)


async def test_admin_set_password_too_short_rejected(client: AsyncClient, test_user: User, make_service_account):
    account, secret = await make_service_account(may_manage_identities=True)
    svc_token = await _service_token(client, account.client_id, secret)
    r = await client.post(
        f"/admin/identities/{test_user.id}/set-password", json={"new_password": "short"},
        headers={"Authorization": f"Bearer {svc_token}"},
    )
    assert r.status_code == 400
