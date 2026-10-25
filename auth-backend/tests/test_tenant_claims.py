from __future__ import annotations

import uuid

from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.tenant_membership import TenantMembership
from app.models.user import User


async def _add_membership(
    db_session: AsyncSession, user: User, *, tenant_id: uuid.UUID | None = None,
    role_name: str = "Nurse-OPD", role_archetype: str = "CLINICIAN",
    facility_ids: list[uuid.UUID] | None = None,
) -> TenantMembership:
    m = TenantMembership(
        user_id=user.id, tenant_id=tenant_id or uuid.uuid4(), tenant_slug="aditya-hospital",
        role_name=role_name, role_archetype=role_archetype, facility_ids=facility_ids or [],
    )
    db_session.add(m)
    await db_session.commit()
    await db_session.refresh(m)
    return m


async def test_login_with_no_membership_is_thin(client: AsyncClient, test_user: User):
    r = await client.post(
        "/auth/login", json={"identifier": "alice@example.test", "password": "correct-horse-battery-staple"},
    )
    access = r.json()["access_token"]
    me = await client.get("/auth/me", headers={"Authorization": f"Bearer {access}"})
    body = me.json()
    assert body["tid"] is None
    assert body["rol"] is None


async def test_login_with_one_membership_auto_binds(client: AsyncClient, test_user: User, db_session: AsyncSession):
    facility_id = uuid.uuid4()
    membership = await _add_membership(db_session, test_user, facility_ids=[facility_id])

    r = await client.post(
        "/auth/login", json={"identifier": "alice@example.test", "password": "correct-horse-battery-staple"},
    )
    access = r.json()["access_token"]
    me = await client.get("/auth/me", headers={"Authorization": f"Bearer {access}"})
    body = me.json()
    assert body["tid"] == str(membership.tenant_id)
    assert body["tsl"] == "aditya-hospital"
    assert body["rol"] == "Nurse-OPD"
    assert body["arc"] == "CLINICIAN"
    assert body["fac"] == [str(facility_id)]


async def test_login_with_two_memberships_requires_tenant_id(
    client: AsyncClient, test_user: User, db_session: AsyncSession
):
    m1 = await _add_membership(db_session, test_user)
    await _add_membership(db_session, test_user)

    r = await client.post(
        "/auth/login", json={"identifier": "alice@example.test", "password": "correct-horse-battery-staple"},
    )
    assert r.status_code == 409
    body = r.json()["detail"]
    assert body["error_code"] == "TENANT_SELECTION_REQUIRED"
    assert str(m1.tenant_id) in body["tenant_ids"]

    r2 = await client.post(
        "/auth/login",
        json={
            "identifier": "alice@example.test", "password": "correct-horse-battery-staple",
            "tenant_id": str(m1.tenant_id),
        },
    )
    assert r2.status_code == 200
    me = await client.get(
        "/auth/me", headers={"Authorization": f"Bearer {r2.json()['access_token']}"},
    )
    assert me.json()["tid"] == str(m1.tenant_id)


async def test_login_for_an_inactive_membership_is_excluded(
    client: AsyncClient, test_user: User, db_session: AsyncSession
):
    m = await _add_membership(db_session, test_user)
    m.is_active = False
    await db_session.commit()

    r = await client.post(
        "/auth/login", json={"identifier": "alice@example.test", "password": "correct-horse-battery-staple"},
    )
    me = await client.get(
        "/auth/me", headers={"Authorization": f"Bearer {r.json()['access_token']}"},
    )
    assert me.json()["tid"] is None


async def test_refresh_preserves_the_tenant_binding(client: AsyncClient, test_user: User, db_session: AsyncSession):
    membership = await _add_membership(db_session, test_user)
    login = await client.post(
        "/auth/login", json={"identifier": "alice@example.test", "password": "correct-horse-battery-staple"},
    )
    refresh_token = login.json()["refresh_token"]

    r = await client.post("/auth/refresh", json={"refresh_token": refresh_token})
    assert r.status_code == 200
    me = await client.get(
        "/auth/me", headers={"Authorization": f"Bearer {r.json()['access_token']}"},
    )
    assert me.json()["tid"] == str(membership.tenant_id)
