from __future__ import annotations

import uuid

from httpx import AsyncClient
from jose import jwt as jose_jwt
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models.tenant_membership import TenantMembership
from app.models.user import User

_HEADERS = {"X-Blumax-Auth-Token-Mint-Key": settings.CORE_TOKEN_MINT_SERVICE_KEY}


def _unverified_claims(token: str) -> dict:
    return jose_jwt.get_unverified_claims(token)


async def test_wrong_key_is_rejected(client: AsyncClient, test_user: User):
    r = await client.post(
        "/internal/tokens/mint-for-verified-identity",
        json={"user_id": str(test_user.id)},
        headers={"X-Blumax-Auth-Token-Mint-Key": "wrong"},
    )
    assert r.status_code == 401


async def test_missing_key_is_rejected(client: AsyncClient, test_user: User):
    r = await client.post(
        "/internal/tokens/mint-for-verified-identity",
        json={"user_id": str(test_user.id)},
    )
    assert r.status_code == 401


async def test_unknown_user_id_is_422(client: AsyncClient):
    r = await client.post(
        "/internal/tokens/mint-for-verified-identity",
        json={"user_id": str(uuid.uuid4())},
        headers=_HEADERS,
    )
    assert r.status_code == 422


async def test_deactivated_user_is_422(client: AsyncClient, test_user: User, db_session: AsyncSession):
    test_user.is_active = False
    db_session.add(test_user)
    await db_session.commit()

    r = await client.post(
        "/internal/tokens/mint-for-verified-identity",
        json={"user_id": str(test_user.id)},
        headers=_HEADERS,
    )
    assert r.status_code == 422


async def test_mints_a_thin_token_with_no_membership(client: AsyncClient, test_user: User):
    """No credential check at all here -- this is the whole point: Core
    already verified the password. A user with no tenant membership gets
    the same thin token login() would have minted for them."""
    r = await client.post(
        "/internal/tokens/mint-for-verified-identity",
        json={"user_id": str(test_user.id)},
        headers=_HEADERS,
    )
    assert r.status_code == 200
    body = r.json()
    claims = _unverified_claims(body["access_token"])
    assert claims["sub"] == str(test_user.id)
    assert claims.get("tid") is None
    assert body["refresh_token"]


async def test_mints_full_claims_for_an_active_membership(
    client: AsyncClient, test_user: User, db_session: AsyncSession,
):
    tenant_id = uuid.uuid4()
    facility_id = uuid.uuid4()
    db_session.add(TenantMembership(
        user_id=test_user.id, tenant_id=tenant_id, tenant_slug="aditya-hospital",
        role_name="Hospital Admin (Full Access)", role_archetype="TENANT_ADMIN",
        facility_ids=[facility_id], is_active=True,
    ))
    await db_session.commit()

    r = await client.post(
        "/internal/tokens/mint-for-verified-identity",
        json={"user_id": str(test_user.id)},
        headers=_HEADERS,
    )
    assert r.status_code == 200
    claims = _unverified_claims(r.json()["access_token"])
    assert claims["tid"] == str(tenant_id)
    assert claims["tsl"] == "aditya-hospital"
    assert claims["rol"] == "Hospital Admin (Full Access)"
    assert claims["arc"] == "TENANT_ADMIN"
    assert claims["fac"] == [str(facility_id)]


async def test_multiple_memberships_without_tenant_id_is_409(
    client: AsyncClient, test_user: User, db_session: AsyncSession,
):
    db_session.add(TenantMembership(
        user_id=test_user.id, tenant_id=uuid.uuid4(), role_name="A", role_archetype="VIEWER",
        facility_ids=[], is_active=True,
    ))
    db_session.add(TenantMembership(
        user_id=test_user.id, tenant_id=uuid.uuid4(), role_name="B", role_archetype="VIEWER",
        facility_ids=[], is_active=True,
    ))
    await db_session.commit()

    r = await client.post(
        "/internal/tokens/mint-for-verified-identity",
        json={"user_id": str(test_user.id)},
        headers=_HEADERS,
    )
    assert r.status_code == 409
    assert r.json()["detail"]["error_code"] == "TENANT_SELECTION_REQUIRED"
    assert len(r.json()["detail"]["tenant_ids"]) == 2


async def test_explicit_tenant_id_picks_that_membership(
    client: AsyncClient, test_user: User, db_session: AsyncSession,
):
    wanted_tenant = uuid.uuid4()
    db_session.add(TenantMembership(
        user_id=test_user.id, tenant_id=uuid.uuid4(), role_name="A", role_archetype="VIEWER",
        facility_ids=[], is_active=True,
    ))
    db_session.add(TenantMembership(
        user_id=test_user.id, tenant_id=wanted_tenant, role_name="B", role_archetype="CLINICIAN",
        facility_ids=[], is_active=True,
    ))
    await db_session.commit()

    r = await client.post(
        "/internal/tokens/mint-for-verified-identity",
        json={"user_id": str(test_user.id), "tenant_id": str(wanted_tenant)},
        headers=_HEADERS,
    )
    assert r.status_code == 200
    claims = _unverified_claims(r.json()["access_token"])
    assert claims["tid"] == str(wanted_tenant)
    assert claims["rol"] == "B"
