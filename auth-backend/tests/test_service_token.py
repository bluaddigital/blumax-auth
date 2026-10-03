from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from cryptography.hazmat.primitives import serialization
from httpx import AsyncClient
from jose import jwt as jose_jwt

from app.core.config import settings
from app.core.keys import ALGORITHM, signing_keys
from app.core.security import InvalidToken, create_service_token, decode_token


# ─── Issuance (HTTP level) ──────────────────────────────────────────────────

async def test_valid_service_token_issued(client: AsyncClient, make_service_account):
    account, secret = await make_service_account(name="svc-valid")
    r = await client.post("/auth/service-token", json={"client_id": account.client_id, "client_secret": secret})
    assert r.status_code == 200
    body = r.json()
    assert body["access_token"]
    assert body["token_type"] == "bearer"
    assert body["expires_in"] == settings.SERVICE_TOKEN_EXPIRE_MINUTES * 60


async def test_wrong_client_secret_rejected(client: AsyncClient, make_service_account):
    account, _secret = await make_service_account(name="svc-wrong-secret")
    r = await client.post("/auth/service-token", json={"client_id": account.client_id, "client_secret": "wrong"})
    assert r.status_code == 401


async def test_unknown_client_id_rejected_with_identical_message(client: AsyncClient, make_service_account):
    account, secret = await make_service_account(name="svc-enum-check")
    r_bad_id = await client.post("/auth/service-token", json={"client_id": "never-existed", "client_secret": "x"})
    r_bad_secret = await client.post("/auth/service-token", json={"client_id": account.client_id, "client_secret": "x"})
    assert r_bad_id.status_code == r_bad_secret.status_code == 401
    assert r_bad_id.json()["detail"] == r_bad_secret.json()["detail"] == "Invalid credentials"


async def test_inactive_service_account_rejected(client: AsyncClient, make_service_account):
    account, secret = await make_service_account(name="svc-inactive", is_active=False)
    r = await client.post("/auth/service-token", json={"client_id": account.client_id, "client_secret": secret})
    assert r.status_code == 401
    assert r.json()["detail"] == "Service account is deactivated"


async def test_issued_service_token_has_type_service_and_name_claim(client: AsyncClient, make_service_account):
    account, secret = await make_service_account(name="svc-claims-check")
    r = await client.post("/auth/service-token", json={"client_id": account.client_id, "client_secret": secret})
    token = r.json()["access_token"]
    claims = decode_token(token, expected_type="service")
    assert claims["sub"] == str(account.id)
    assert claims["snm"] == "svc-claims-check"
    assert claims["iss"] == settings.JWT_ISSUER
    assert claims["aud"] == settings.JWT_AUDIENCE
    # No role/tenant/facility/scope claim of any kind -- the token is as
    # thin as a human one, see ServiceTokenClaims's own docstring.
    assert set(claims.keys()) == {"iss", "aud", "sub", "type", "snm", "jti", "iat", "exp"}


async def test_deactivated_after_mint_is_rejected_on_next_use(client: AsyncClient, make_service_account, db_session):
    """Re-resolved fresh, not trusted from the token alone: a still-
    unexpired service token for an account deactivated AFTER mint must stop
    working on its very next use."""
    account, secret = await make_service_account(name="svc-deactivate-after-mint", destination_app="labs")
    r = await client.post("/auth/service-token", json={"client_id": account.client_id, "client_secret": secret})
    token = r.json()["access_token"]

    account.is_active = False
    db_session.add(account)
    await db_session.commit()

    r2 = await client.post("/auth/sso/exchange", json={"code": "whatever"}, headers={"Authorization": f"Bearer {token}"})
    assert r2.status_code == 401
    assert r2.json()["detail"] == "Service account is deactivated"


# ─── decode_token-level security properties, mirroring test_jwt.py but for type="service" ──

def test_valid_service_token_decodes():
    token, jti = create_service_token(service_account_id=uuid.uuid4(), name="svc-x")
    claims = decode_token(token, expected_type="service")
    assert claims["jti"] == jti
    assert claims["type"] == "service"


def test_service_token_wrong_type_rejected():
    """A genuine service token must not verify as "access" -- the SAME
    type-confusion protection decode_token already gives human tokens."""
    token, _ = create_service_token(service_account_id=uuid.uuid4(), name="svc-x")
    with pytest.raises(InvalidToken):
        decode_token(token, expected_type="access")


def test_access_token_wrong_type_rejected_as_service():
    from app.core.security import create_access_token

    token, _ = create_access_token(user_id=uuid.uuid4())
    with pytest.raises(InvalidToken):
        decode_token(token, expected_type="service")


def test_service_token_wrong_issuer_rejected():
    keys = signing_keys()
    now = datetime.now(UTC)
    token = jose_jwt.encode(
        {
            "iss": "https://not-blumax-auth.example", "aud": settings.JWT_AUDIENCE,
            "sub": str(uuid.uuid4()), "type": "service", "snm": "svc-x", "jti": str(uuid.uuid4()),
            "iat": now, "exp": now + timedelta(minutes=5),
        },
        keys.private_pem(), algorithm=ALGORITHM, headers={"kid": keys.kid},
    )
    with pytest.raises(InvalidToken):
        decode_token(token, expected_type="service")


def test_service_token_wrong_audience_rejected():
    keys = signing_keys()
    now = datetime.now(UTC)
    token = jose_jwt.encode(
        {
            "iss": settings.JWT_ISSUER, "aud": "not-blumax", "sub": str(uuid.uuid4()),
            "type": "service", "snm": "svc-x", "jti": str(uuid.uuid4()),
            "iat": now, "exp": now + timedelta(minutes=5),
        },
        keys.private_pem(), algorithm=ALGORITHM, headers={"kid": keys.kid},
    )
    with pytest.raises(InvalidToken):
        decode_token(token, expected_type="service")


def test_service_token_expired_rejected():
    keys = signing_keys()
    now = datetime.now(UTC)
    token = jose_jwt.encode(
        {
            "iss": settings.JWT_ISSUER, "aud": settings.JWT_AUDIENCE, "sub": str(uuid.uuid4()),
            "type": "service", "snm": "svc-x", "jti": str(uuid.uuid4()),
            "iat": now - timedelta(minutes=20), "exp": now - timedelta(minutes=5),
        },
        keys.private_pem(), algorithm=ALGORITHM, headers={"kid": keys.kid},
    )
    with pytest.raises(InvalidToken):
        decode_token(token, expected_type="service")


def test_service_token_unknown_kid_rejected():
    keys = signing_keys()
    now = datetime.now(UTC)
    token = jose_jwt.encode(
        {
            "iss": settings.JWT_ISSUER, "aud": settings.JWT_AUDIENCE, "sub": str(uuid.uuid4()),
            "type": "service", "snm": "svc-x", "jti": str(uuid.uuid4()),
            "iat": now, "exp": now + timedelta(minutes=5),
        },
        keys.private_pem(), algorithm=ALGORITHM, headers={"kid": "not-a-real-kid"},
    )
    with pytest.raises(InvalidToken):
        decode_token(token, expected_type="service")


def test_service_token_wrong_signature_rejected():
    """Signed with a DIFFERENT (freshly generated) private key, claiming
    the real kid -- must fail signature verification, distinct from the
    unknown-kid case above."""
    from cryptography.hazmat.primitives.asymmetric import rsa

    real_keys = signing_keys()
    other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    other_pem = other_key.private_bytes(
        encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    now = datetime.now(UTC)
    token = jose_jwt.encode(
        {
            "iss": settings.JWT_ISSUER, "aud": settings.JWT_AUDIENCE, "sub": str(uuid.uuid4()),
            "type": "service", "snm": "svc-x", "jti": str(uuid.uuid4()),
            "iat": now, "exp": now + timedelta(minutes=5),
        },
        other_pem, algorithm=ALGORITHM, headers={"kid": real_keys.kid},  # real kid, wrong key
    )
    with pytest.raises(InvalidToken):
        decode_token(token, expected_type="service")
