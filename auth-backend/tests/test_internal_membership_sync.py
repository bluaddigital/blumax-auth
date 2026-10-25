from __future__ import annotations

import uuid

from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models.tenant_membership import TenantMembership
from app.models.user import User

_HEADERS = {"X-Blumax-Auth-User-Sync-Key": settings.CORE_USER_SYNC_SERVICE_KEY}


async def test_wrong_key_is_rejected(client: AsyncClient):
    r = await client.post(
        "/internal/memberships/sync",
        json={
            "user_id": str(uuid.uuid4()), "tenant_id": str(uuid.uuid4()),
            "role_name": "Nurse-OPD", "role_archetype": "CLINICIAN",
        },
        headers={"X-Blumax-Auth-User-Sync-Key": "wrong"},
    )
    assert r.status_code == 401


async def test_creates_a_new_membership(client: AsyncClient, test_user: User, db_session: AsyncSession):
    tenant_id = uuid.uuid4()
    facility_id = uuid.uuid4()
    r = await client.post(
        "/internal/memberships/sync",
        json={
            "user_id": str(test_user.id), "tenant_id": str(tenant_id), "tenant_slug": "aditya-hospital",
            "role_name": "Billing-OPD", "role_archetype": "VIEWER", "facility_ids": [str(facility_id)],
        },
        headers=_HEADERS,
    )
    assert r.status_code == 204

    row = (
        await db_session.execute(
            TenantMembership.__table__.select().where(TenantMembership.user_id == test_user.id)
        )
    ).first()
    assert row is not None
    assert row.role_name == "Billing-OPD"
    assert row.facility_ids == [facility_id]


async def test_resync_replaces_the_role_in_place(client: AsyncClient, test_user: User, db_session: AsyncSession):
    tenant_id = uuid.uuid4()
    await client.post(
        "/internal/memberships/sync",
        json={
            "user_id": str(test_user.id), "tenant_id": str(tenant_id),
            "role_name": "Nurse-OPD", "role_archetype": "CLINICIAN",
        },
        headers=_HEADERS,
    )
    r = await client.post(
        "/internal/memberships/sync",
        json={
            "user_id": str(test_user.id), "tenant_id": str(tenant_id),
            "role_name": "Nurse Manager-OPD", "role_archetype": "CLINICIAN",
        },
        headers=_HEADERS,
    )
    assert r.status_code == 204

    rows = (
        await db_session.execute(
            TenantMembership.__table__.select().where(TenantMembership.user_id == test_user.id)
        )
    ).all()
    assert len(rows) == 1
    assert rows[0].role_name == "Nurse Manager-OPD"


async def test_revoke_marks_the_membership_inactive(client: AsyncClient, test_user: User, db_session: AsyncSession):
    tenant_id = uuid.uuid4()
    await client.post(
        "/internal/memberships/sync",
        json={
            "user_id": str(test_user.id), "tenant_id": str(tenant_id),
            "role_name": "Nurse-OPD", "role_archetype": "CLINICIAN",
        },
        headers=_HEADERS,
    )

    r = await client.post(
        "/internal/memberships/revoke",
        json={"user_id": str(test_user.id), "tenant_id": str(tenant_id)},
        headers=_HEADERS,
    )
    assert r.status_code == 204

    row = (
        await db_session.execute(
            TenantMembership.__table__.select().where(TenantMembership.user_id == test_user.id)
        )
    ).first()
    assert row.is_active is False


async def test_revoke_for_an_unknown_membership_is_a_harmless_noop(client: AsyncClient):
    r = await client.post(
        "/internal/memberships/revoke",
        json={"user_id": str(uuid.uuid4()), "tenant_id": str(uuid.uuid4())},
        headers=_HEADERS,
    )
    assert r.status_code == 204
