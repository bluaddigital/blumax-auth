from __future__ import annotations

import asyncio
import uuid

import pytest
from httpx import AsyncClient
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.sso_code import SsoCodeUnavailableError, consume_code, mint_code
from app.models.user import User


async def _login(client: AsyncClient) -> str:
    r = await client.post(
        "/auth/login", json={"identifier": "alice@example.test", "password": "correct-horse-battery-staple"}
    )
    assert r.status_code == 200
    return r.json()["access_token"]


async def _service_token(client: AsyncClient, client_id: str, client_secret: str) -> str:
    r = await client.post("/auth/service-token", json={"client_id": client_id, "client_secret": client_secret})
    assert r.status_code == 200, r.text
    return r.json()["access_token"]


# ─── Valid end-to-end exchange ────────────────────────────────────────────

async def test_valid_mint_and_exchange(client: AsyncClient, test_user: User, make_service_account):
    access_token = await _login(client)
    r = await client.post(
        "/auth/sso/code", json={"destination_app": "labs"},
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert r.status_code == 200
    code = r.json()["code"]
    assert r.json()["expires_in"] == settings.SSO_CODE_TTL_SECONDS

    account, secret = await make_service_account(destination_app="labs")
    svc_token = await _service_token(client, account.client_id, secret)

    r2 = await client.post(
        "/auth/sso/exchange", json={"code": code}, headers={"Authorization": f"Bearer {svc_token}"},
    )
    assert r2.status_code == 200
    body = r2.json()
    assert body["access_token"]
    assert body["token_type"] == "bearer"

    # And the exchanged token is a genuine, independently-verifiable access
    # token for the SAME user -- not a bare echo of the code.
    r3 = await client.get("/auth/me", headers={"Authorization": f"Bearer {body['access_token']}"})
    assert r3.status_code == 200
    assert r3.json()["sub"] == str(test_user.id)
    assert r3.json()["type"] == "access"


async def test_exchange_never_returns_a_refresh_token(client: AsyncClient, test_user: User, make_service_account):
    access_token = await _login(client)
    r = await client.post(
        "/auth/sso/code", json={"destination_app": "labs"}, headers={"Authorization": f"Bearer {access_token}"},
    )
    code = r.json()["code"]
    account, secret = await make_service_account(destination_app="labs")
    svc_token = await _service_token(client, account.client_id, secret)
    r2 = await client.post("/auth/sso/exchange", json={"code": code}, headers={"Authorization": f"Bearer {svc_token}"})
    assert "refresh_token" not in r2.json()


# ─── Expired code ──────────────────────────────────────────────────────────

async def test_expired_code_rejected(client: AsyncClient, test_user: User, make_service_account):
    original_ttl = settings.SSO_CODE_TTL_SECONDS
    settings.SSO_CODE_TTL_SECONDS = 1
    try:
        access_token = await _login(client)
        r = await client.post(
            "/auth/sso/code", json={"destination_app": "labs"}, headers={"Authorization": f"Bearer {access_token}"},
        )
        code = r.json()["code"]
        await asyncio.sleep(1.5)  # let Redis's own TTL actually expire the key

        account, secret = await make_service_account(destination_app="labs")
        svc_token = await _service_token(client, account.client_id, secret)
        r2 = await client.post("/auth/sso/exchange", json={"code": code}, headers={"Authorization": f"Bearer {svc_token}"})
        assert r2.status_code == 401
        assert r2.json()["detail"] == "Invalid or expired code"
    finally:
        settings.SSO_CODE_TTL_SECONDS = original_ttl


# ─── Replayed code ──────────────────────────────────────────────────────────

async def test_replayed_code_rejected_on_second_attempt(client: AsyncClient, test_user: User, make_service_account):
    access_token = await _login(client)
    r = await client.post(
        "/auth/sso/code", json={"destination_app": "labs"}, headers={"Authorization": f"Bearer {access_token}"},
    )
    code = r.json()["code"]
    account, secret = await make_service_account(destination_app="labs")
    svc_token = await _service_token(client, account.client_id, secret)

    r1 = await client.post("/auth/sso/exchange", json={"code": code}, headers={"Authorization": f"Bearer {svc_token}"})
    assert r1.status_code == 200
    r2 = await client.post("/auth/sso/exchange", json={"code": code}, headers={"Authorization": f"Bearer {svc_token}"})
    assert r2.status_code == 401
    assert r2.json()["detail"] == "Invalid or expired code"


# ─── Wrong destination / wrong application ─────────────────────────────────

async def test_wrong_destination_application_rejected(client: AsyncClient, test_user: User, make_service_account):
    """A code minted for "labs" must not be redeemable by a service
    account registered for a DIFFERENT destination_app ("pharmacy")."""
    access_token = await _login(client)
    r = await client.post(
        "/auth/sso/code", json={"destination_app": "labs"}, headers={"Authorization": f"Bearer {access_token}"},
    )
    code = r.json()["code"]

    pharmacy_account, pharmacy_secret = await make_service_account(destination_app="pharmacy")
    svc_token = await _service_token(client, pharmacy_account.client_id, pharmacy_secret)

    r2 = await client.post("/auth/sso/exchange", json={"code": code}, headers={"Authorization": f"Bearer {svc_token}"})
    assert r2.status_code == 401
    assert r2.json()["detail"] == "Invalid or expired code"


async def test_service_with_no_destination_cannot_exchange_anything(client: AsyncClient, test_user: User, make_service_account):
    access_token = await _login(client)
    r = await client.post(
        "/auth/sso/code", json={"destination_app": "labs"}, headers={"Authorization": f"Bearer {access_token}"},
    )
    code = r.json()["code"]

    account, secret = await make_service_account(destination_app=None)
    svc_token = await _service_token(client, account.client_id, secret)
    r2 = await client.post("/auth/sso/exchange", json={"code": code}, headers={"Authorization": f"Bearer {svc_token}"})
    assert r2.status_code == 401


# ─── Random invalid code ───────────────────────────────────────────────────

async def test_random_invalid_code_rejected(client: AsyncClient, make_service_account):
    account, secret = await make_service_account(destination_app="labs")
    svc_token = await _service_token(client, account.client_id, secret)
    r = await client.post(
        "/auth/sso/exchange", json={"code": "this-was-never-a-real-code"},
        headers={"Authorization": f"Bearer {svc_token}"},
    )
    assert r.status_code == 401
    assert r.json()["detail"] == "Invalid or expired code"


# ─── Redis unavailable ──────────────────────────────────────────────────────

async def test_mint_code_fails_closed_when_redis_unavailable(monkeypatch):
    class _BoomRedis:
        async def set(self, *a, **kw):
            raise ConnectionError("redis down")

    with pytest.raises(SsoCodeUnavailableError):
        await mint_code(_BoomRedis(), user_id=str(uuid.uuid4()), destination_app="labs", issued_by=None)


async def test_consume_code_fails_closed_when_redis_unavailable(monkeypatch):
    class _BoomRedis:
        async def getdel(self, *a, **kw):
            raise ConnectionError("redis down")

    with pytest.raises(SsoCodeUnavailableError):
        await consume_code(_BoomRedis(), "some-code")


async def test_exchange_route_returns_503_when_redis_unavailable(
    client: AsyncClient, make_service_account, monkeypatch,
):
    import app.services.sso_service as sso_service_module

    async def _boom(*a, **kw):
        raise SsoCodeUnavailableError("redis down")

    monkeypatch.setattr(sso_service_module, "consume_code", _boom)
    account, secret = await make_service_account(destination_app="labs")
    svc_token = await _service_token(client, account.client_id, secret)
    r = await client.post("/auth/sso/exchange", json={"code": "whatever"}, headers={"Authorization": f"Bearer {svc_token}"})
    assert r.status_code == 503


# ─── Concurrent consumption ─────────────────────────────────────────────────

async def test_concurrent_consumption_only_one_wins(test_user: User, make_service_account, db_session: AsyncSession):
    """Direct proof of atomicity against REAL Redis (not mocked): two
    parallel consume_code() calls for the SAME code must not both
    succeed."""
    import redis.asyncio as aioredis

    redis = aioredis.from_url(settings.REDIS_URL, decode_responses=True)
    try:
        code = await mint_code(redis, user_id=str(test_user.id), destination_app="labs", issued_by=None)
        results = await asyncio.gather(
            consume_code(redis, code), consume_code(redis, code), consume_code(redis, code),
        )
        successes = [r for r in results if r is not None]
        assert len(successes) == 1
        assert successes[0].user_id == str(test_user.id)
    finally:
        await redis.aclose()


# ─── Mint-on-behalf scope (least privilege) ────────────────────────────────

async def test_mint_on_behalf_denied_without_scope(client: AsyncClient, test_user: User, make_service_account):
    account, secret = await make_service_account(may_mint_on_behalf=False)
    svc_token = await _service_token(client, account.client_id, secret)
    r = await client.post(
        "/auth/sso/code/on-behalf", json={"user_id": str(test_user.id), "destination_app": "labs"},
        headers={"Authorization": f"Bearer {svc_token}"},
    )
    assert r.status_code == 403


async def test_mint_on_behalf_denied_for_unlisted_destination(client: AsyncClient, test_user: User, make_service_account):
    """Least privilege: may_mint_on_behalf=True is not enough on its own --
    the specific destination must also be in allowed_mint_destinations."""
    account, secret = await make_service_account(may_mint_on_behalf=True, allowed_mint_destinations=["pharmacy"])
    svc_token = await _service_token(client, account.client_id, secret)
    r = await client.post(
        "/auth/sso/code/on-behalf", json={"user_id": str(test_user.id), "destination_app": "labs"},
        headers={"Authorization": f"Bearer {svc_token}"},
    )
    assert r.status_code == 403


async def test_mint_on_behalf_succeeds_for_allowed_destination(client: AsyncClient, test_user: User, make_service_account):
    account, secret = await make_service_account(may_mint_on_behalf=True, allowed_mint_destinations=["labs"])
    svc_token = await _service_token(client, account.client_id, secret)
    r = await client.post(
        "/auth/sso/code/on-behalf", json={"user_id": str(test_user.id), "destination_app": "labs"},
        headers={"Authorization": f"Bearer {svc_token}"},
    )
    assert r.status_code == 200
    assert r.json()["code"]


async def test_mint_on_behalf_for_unknown_user_rejected(client: AsyncClient, make_service_account):
    account, secret = await make_service_account(may_mint_on_behalf=True, allowed_mint_destinations=["labs"])
    svc_token = await _service_token(client, account.client_id, secret)
    r = await client.post(
        "/auth/sso/code/on-behalf", json={"user_id": str(uuid.uuid4()), "destination_app": "labs"},
        headers={"Authorization": f"Bearer {svc_token}"},
    )
    assert r.status_code == 403


async def test_human_token_rejected_on_service_only_routes(client: AsyncClient, test_user: User):
    """A human access token presented where a service token is required
    must be rejected -- decode_token's expected_type check, not an
    endpoint-specific guess."""
    access_token = await _login(client)
    r = await client.post(
        "/auth/sso/exchange", json={"code": "whatever"}, headers={"Authorization": f"Bearer {access_token}"},
    )
    assert r.status_code == 401


async def test_service_token_rejected_on_human_only_routes(client: AsyncClient, make_service_account):
    """And the reverse: a service token must not be accepted where a
    human token is required (e.g. minting a code for "yourself")."""
    account, secret = await make_service_account(destination_app="labs")
    svc_token = await _service_token(client, account.client_id, secret)
    r = await client.post(
        "/auth/sso/code", json={"destination_app": "labs"}, headers={"Authorization": f"Bearer {svc_token}"},
    )
    assert r.status_code == 401
