"""Tenant-scoped staff identity (owner decision 2026-11-28):

  "One tenant = one customer hospital organization = its own staff
   identity namespace."

Ravi at Apollo and Ravi at Yashoda are two separate accounts with
different ids, credentials and roles, never linked automatically, and a
token carries exactly one tenant with that tenant's account id as `sub`.
"""
from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.security import verify_password_constant_time
from app.models.tenant_membership import TenantMembership
from app.models.user import User

APOLLO = uuid.UUID("11111111-1111-4111-8111-111111111111")
YASHODA = uuid.UUID("22222222-2222-4222-8222-222222222222")
APOLLO_PW = "apollo-ravi-password-1"
YASHODA_PW = "yashoda-ravi-password-1"
REVEAL = {"X-Dev-Tooling-Reveal-Key": settings.DEV_TOOLING_RESET_CODE_REVEAL_KEY}
SYNC = {"X-Blumax-Auth-User-Sync-Key": settings.CORE_USER_SYNC_SERVICE_KEY}


@pytest.fixture
def mode_on(monkeypatch):
    monkeypatch.setattr(settings, "TENANT_SCOPED_IDENTITY_MODE", "on")


async def _admin_headers(client: AsyncClient, make_service_account) -> dict:
    account, secret = await make_service_account(may_manage_identities=True)
    r = await client.post("/auth/service-token", json={"client_id": account.client_id, "client_secret": secret})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


async def _create(client, headers, *, tenant_id, password, tenant_slug=None,
                  identifier="ravi@example.test", username="ravi"):
    body = {"identifier": identifier, "username": username, "password": password, "tenant_id": str(tenant_id)}
    if tenant_slug is not None:
        body["tenant_slug"] = tenant_slug
    return await client.post("/admin/identities", json=body, headers=headers)


@pytest.fixture
async def two_ravis(client: AsyncClient, make_service_account, mode_on) -> dict:
    headers = await _admin_headers(client, make_service_account)
    a = await _create(client, headers, tenant_id=APOLLO, tenant_slug="apollo", password=APOLLO_PW)
    y = await _create(client, headers, tenant_id=YASHODA, tenant_slug="Yashoda", password=YASHODA_PW)
    assert a.status_code == 201, a.text
    assert y.status_code == 201, y.text
    return {"apollo": a.json()["id"], "yashoda": y.json()["id"], "headers": headers}


async def _login(client, *, tenant, password, identifier="ravi", **extra):
    body = {"identifier": identifier, "password": password, **extra}
    if tenant is not None:
        body["tenant"] = tenant
    return await client.post("/auth/login", json=body)


async def _me(client, access):
    return await client.get("/auth/me", headers={"Authorization": f"Bearer {access}"})


# --- identity creation -------------------------------------------------------


async def test_mode_off_refuses_tenant_scoped_creation(client: AsyncClient, make_service_account):
    assert settings.TENANT_SCOPED_IDENTITY_MODE == "off"  # the default
    headers = await _admin_headers(client, make_service_account)
    r = await _create(client, headers, tenant_id=APOLLO, password=APOLLO_PW)
    assert r.status_code == 400


async def test_same_username_in_two_tenants_is_two_accounts(two_ravis, db_session: AsyncSession):
    assert two_ravis["apollo"] != two_ravis["yashoda"]
    rows = (await db_session.execute(select(User).order_by(User.tenant_id))).scalars().all()
    assert [(r.tenant_id, r.username_normalized, r.identifier) for r in rows] == [
        (APOLLO, "ravi", "ravi@example.test"), (YASHODA, "ravi", "ravi@example.test"),
    ]


@pytest.mark.parametrize("identifier,username", [
    ("other@example.test", "RAVI "),          # same username, different case/space
    ("RAVI@example.test", "someone-else"),    # same email, different case
    ("ravi", "x"),                            # identifier equal to another account's username
])
async def test_duplicate_in_same_tenant_rejected(client, two_ravis, identifier, username):
    r = await _create(client, two_ravis["headers"], tenant_id=APOLLO, password="p-123456789",
                      identifier=identifier, username=username)
    assert r.status_code == 409, r.text


async def test_tenant_slug_cannot_be_repointed(client, two_ravis):
    r = await _create(client, two_ravis["headers"], tenant_id=uuid.uuid4(), tenant_slug="apollo",
                      password="p-123456789", identifier="new@example.test", username="new")
    assert r.status_code == 409
    r = await _create(client, two_ravis["headers"], tenant_id=APOLLO, tenant_slug="apollo-2",
                      password="p-123456789", identifier="new@example.test", username="new")
    assert r.status_code == 409


async def test_global_identity_creation_unchanged_and_independent_of_tenant_rows(client, two_ravis):
    # A global account may reuse a name that exists inside tenants -- the
    # namespaces are disjoint.
    r = await client.post("/admin/identities", json={
        "identifier": "ravi@example.test", "username": "ravi", "password": "global-pw-123",
    }, headers=two_ravis["headers"])
    assert r.status_code == 201, r.text
    assert r.json()["tenant_id"] is None
    r = await client.post("/admin/identities", json={
        "identifier": "ravi@example.test", "password": "global-pw-123",
    }, headers=two_ravis["headers"])
    assert r.status_code == 409


# --- login -------------------------------------------------------------------


async def test_each_tenant_password_authenticates_only_its_own_account(client, two_ravis):
    ok_a = await _login(client, tenant="apollo", password=APOLLO_PW)
    ok_y = await _login(client, tenant="YASHODA", password=YASHODA_PW)
    assert ok_a.status_code == 200 and ok_y.status_code == 200

    me_a = (await _me(client, ok_a.json()["access_token"])).json()
    me_y = (await _me(client, ok_y.json()["access_token"])).json()
    assert (me_a["sub"], me_a["tid"], me_a["tsl"]) == (two_ravis["apollo"], str(APOLLO), "apollo")
    assert (me_y["sub"], me_y["tid"], me_y["tsl"]) == (two_ravis["yashoda"], str(YASHODA), "yashoda")
    assert me_a["arc"] == "VIEWER" and me_a["fac"] == []  # no membership -> most restrictive

    # One tenant's password never authenticates the other tenant's account.
    assert (await _login(client, tenant="yashoda", password=APOLLO_PW)).status_code == 401
    assert (await _login(client, tenant="apollo", password=YASHODA_PW)).status_code == 401
    # By email, by tenant UUID.
    r = await _login(client, tenant=str(APOLLO), password=APOLLO_PW, identifier="Ravi@Example.test")
    assert r.status_code == 200
    assert (await _me(client, r.json()["access_token"])).json()["sub"] == two_ravis["apollo"]


async def test_tenant_scoped_account_unreachable_without_tenant(client, two_ravis):
    assert (await _login(client, tenant=None, password=APOLLO_PW)).status_code == 401
    assert (await _login(client, tenant=None, password=APOLLO_PW,
                         identifier="ravi@example.test")).status_code == 401


async def test_unknown_tenant_and_conflicting_tenant_id_refused(client, two_ravis):
    assert (await _login(client, tenant="no-such-hospital", password=APOLLO_PW)).status_code == 401
    r = await _login(client, tenant="apollo", password=APOLLO_PW, tenant_id=str(YASHODA))
    assert r.status_code == 401


async def test_membership_of_another_tenant_never_used(client, two_ravis, db_session: AsyncSession):
    db_session.add(TenantMembership(
        user_id=uuid.UUID(two_ravis["apollo"]), tenant_id=APOLLO, tenant_slug="apollo",
        role_name="Pharmacist", role_archetype="CLINICIAN", facility_ids=[],
    ))
    await db_session.commit()
    r = await _login(client, tenant="apollo", password=APOLLO_PW)
    me = (await _me(client, r.json()["access_token"])).json()
    assert (me["tid"], me["rol"], me["arc"]) == (str(APOLLO), "Pharmacist", "CLINICIAN")

    # Core's membership push for a tenant-scoped account naming another tenant is refused.
    r = await client.post("/internal/memberships/sync", headers=SYNC, json={
        "user_id": two_ravis["apollo"], "tenant_id": str(YASHODA), "role_name": "Admin",
    })
    assert r.status_code == 409
    rows = (await db_session.execute(select(TenantMembership))).scalars().all()
    assert [(m.user_id, m.tenant_id) for m in rows] == [(uuid.UUID(two_ravis["apollo"]), APOLLO)]


async def test_core_user_sync_cannot_rewrite_tenant_scoped_account(client, two_ravis, db_session):
    r = await client.post("/internal/users/sync", headers=SYNC, json={
        "user_id": two_ravis["apollo"], "identifier": "x@example.test", "hashed_password": "$2b$12$x",
    })
    assert r.status_code == 409
    row = await db_session.get(User, uuid.UUID(two_ravis["apollo"]))
    await db_session.refresh(row)
    assert verify_password_constant_time(APOLLO_PW, row.hashed_password)


async def test_legacy_global_user_keeps_working_with_mode_on(client, test_user: User, mode_on, db_session):
    r = await client.post("/auth/login", json={
        "identifier": "alice@example.test", "password": "correct-horse-battery-staple",
    })
    assert r.status_code == 200
    # With a tenant: bound through its membership in that tenant only.
    db_session.add(TenantMembership(
        user_id=test_user.id, tenant_id=APOLLO, tenant_slug="apollo", role_name="Nurse", role_archetype="CLINICIAN",
        facility_ids=[],
    ))
    await db_session.commit()
    r = await _login(client, tenant=str(APOLLO), identifier="alice", password="correct-horse-battery-staple")
    assert r.status_code == 200
    me = (await _me(client, r.json()["access_token"])).json()
    assert (me["sub"], me["tid"]) == (str(test_user.id), str(APOLLO))
    r = await _login(client, tenant=str(YASHODA), identifier="alice", password="correct-horse-battery-staple")
    assert r.status_code == 401


async def test_mode_off_ignores_tenant_field(client, test_user: User):
    r = await _login(client, tenant="anything", identifier="alice@example.test",
                     password="correct-horse-battery-staple")
    assert r.status_code == 200
    assert (await _me(client, r.json()["access_token"])).json()["tid"] is None


# --- refresh / logout / revocation / reset stay tenant-bound ------------------


async def test_refresh_stays_bound_to_own_tenant(client, two_ravis):
    refresh = (await _login(client, tenant="apollo", password=APOLLO_PW)).json()["refresh_token"]
    r = await client.post("/auth/refresh", json={"refresh_token": refresh, "tenant_id": str(YASHODA)})
    assert r.status_code == 401

    refresh = (await _login(client, tenant="apollo", password=APOLLO_PW)).json()["refresh_token"]
    r = await client.post("/auth/refresh", json={"refresh_token": refresh})
    assert r.status_code == 200
    me = (await _me(client, r.json()["access_token"])).json()
    assert (me["sub"], me["tid"]) == (two_ravis["apollo"], str(APOLLO))


async def test_logout_everywhere_in_one_tenant_leaves_the_other_alone(client, two_ravis):
    a = (await _login(client, tenant="apollo", password=APOLLO_PW)).json()
    y = (await _login(client, tenant="yashoda", password=YASHODA_PW)).json()
    r = await client.post("/auth/logout", json={"refresh_token": a["refresh_token"], "all_devices": True})
    assert r.status_code == 204
    assert (await _me(client, a["access_token"])).status_code == 401
    assert (await _me(client, y["access_token"])).status_code == 200
    assert (await client.post("/auth/refresh", json={"refresh_token": y["refresh_token"]})).status_code == 200


async def test_password_reset_is_tenant_bound(client, two_ravis, db_session):
    y = (await _login(client, tenant="yashoda", password=YASHODA_PW)).json()

    # Without a tenant, a tenant-scoped account is not found (no code issued).
    r = await client.post("/auth/password-reset/request", json={"identifier": "ravi@example.test"}, headers=REVEAL)
    assert r.status_code == 202 and "dev_reset_code" not in r.json()

    r = await client.post("/auth/password-reset/request",
                          json={"identifier": "ravi", "tenant": "apollo"}, headers=REVEAL)
    code = r.json()["dev_reset_code"]
    r = await client.post("/auth/password-reset/confirm", json={"reset_code": code, "new_password": "new-apollo-pw-1"})
    assert r.status_code == 204

    assert (await _login(client, tenant="apollo", password="new-apollo-pw-1")).status_code == 200
    assert (await _login(client, tenant="apollo", password=APOLLO_PW)).status_code == 401
    # Yashoda's ravi: same password, same live session.
    assert (await _login(client, tenant="yashoda", password=YASHODA_PW)).status_code == 200
    assert (await _me(client, y["access_token"])).status_code == 200
    assert (await client.post("/auth/refresh", json={"refresh_token": y["refresh_token"]})).status_code == 200


async def test_admin_deactivate_is_per_account(client, two_ravis):
    r = await client.post(f"/admin/identities/{two_ravis['apollo']}/deactivate", headers=two_ravis["headers"])
    assert r.status_code == 204
    assert (await _login(client, tenant="apollo", password=APOLLO_PW)).status_code == 401
    assert (await _login(client, tenant="yashoda", password=YASHODA_PW)).status_code == 200
