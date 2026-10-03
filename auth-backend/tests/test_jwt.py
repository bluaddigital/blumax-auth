from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from cryptography.hazmat.primitives import serialization
from jose import jwt as jose_jwt

from app.core.config import settings
from app.core.keys import ALGORITHM, signing_keys
from app.core.security import InvalidToken, create_access_token, decode_token


def test_valid_access_token_decodes():
    token, jti = create_access_token(user_id=uuid.uuid4())
    claims = decode_token(token, expected_type="access")
    assert claims["jti"] == jti
    assert claims["type"] == "access"
    assert claims["iss"] == settings.JWT_ISSUER
    assert claims["aud"] == settings.JWT_AUDIENCE


def test_invalid_signature_rejected():
    token, _ = create_access_token(user_id=uuid.uuid4())
    tampered = token[:-4] + ("AAAA" if token[-4:] != "AAAA" else "BBBB")
    with pytest.raises(InvalidToken):
        decode_token(tampered, expected_type="access")


def test_expired_token_rejected():
    keys = signing_keys()
    now = datetime.now(UTC)
    token = jose_jwt.encode(
        {
            "iss": settings.JWT_ISSUER, "aud": settings.JWT_AUDIENCE, "sub": str(uuid.uuid4()),
            "type": "access", "jti": str(uuid.uuid4()),
            "iat": now - timedelta(minutes=20), "exp": now - timedelta(minutes=5),
        },
        keys.private_pem(), algorithm=ALGORITHM, headers={"kid": keys.kid},
    )
    with pytest.raises(InvalidToken):
        decode_token(token, expected_type="access")


def test_wrong_issuer_rejected():
    keys = signing_keys()
    now = datetime.now(UTC)
    token = jose_jwt.encode(
        {
            "iss": "https://not-blumax-auth.example", "aud": settings.JWT_AUDIENCE,
            "sub": str(uuid.uuid4()), "type": "access", "jti": str(uuid.uuid4()),
            "iat": now, "exp": now + timedelta(minutes=5),
        },
        keys.private_pem(), algorithm=ALGORITHM, headers={"kid": keys.kid},
    )
    with pytest.raises(InvalidToken):
        decode_token(token, expected_type="access")


def test_wrong_audience_rejected():
    keys = signing_keys()
    now = datetime.now(UTC)
    token = jose_jwt.encode(
        {
            "iss": settings.JWT_ISSUER, "aud": "not-blumax", "sub": str(uuid.uuid4()),
            "type": "access", "jti": str(uuid.uuid4()),
            "iat": now, "exp": now + timedelta(minutes=5),
        },
        keys.private_pem(), algorithm=ALGORITHM, headers={"kid": keys.kid},
    )
    with pytest.raises(InvalidToken):
        decode_token(token, expected_type="access")


def test_unknown_kid_rejected():
    keys = signing_keys()
    now = datetime.now(UTC)
    token = jose_jwt.encode(
        {
            "iss": settings.JWT_ISSUER, "aud": settings.JWT_AUDIENCE, "sub": str(uuid.uuid4()),
            "type": "access", "jti": str(uuid.uuid4()),
            "iat": now, "exp": now + timedelta(minutes=5),
        },
        keys.private_pem(), algorithm=ALGORITHM, headers={"kid": "not-a-real-kid"},
    )
    with pytest.raises(InvalidToken):
        decode_token(token, expected_type="access")


def test_wrong_token_type_rejected():
    token, _ = create_access_token(user_id=uuid.uuid4())
    with pytest.raises(InvalidToken):
        decode_token(token, expected_type="refresh")


def _b64url(data: bytes) -> str:
    import base64
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def test_alg_none_attack_rejected():
    """Classic JWT attack: an attacker crafts a token with alg=none and no
    signature, hoping a lax verifier skips signature checking entirely.
    Hand-built: jose's own encode() refuses to construct this (it checks
    for exactly this pattern), so a real attacker's tool -- not jose --
    is what this test stands in for."""
    import json

    now = datetime.now(UTC)
    header = {"alg": "none", "typ": "JWT"}
    payload = {
        "iss": settings.JWT_ISSUER, "aud": settings.JWT_AUDIENCE, "sub": str(uuid.uuid4()),
        "type": "access", "jti": str(uuid.uuid4()),
        "iat": int(now.timestamp()), "exp": int((now + timedelta(minutes=5)).timestamp()),
    }
    forged = f"{_b64url(json.dumps(header).encode())}.{_b64url(json.dumps(payload).encode())}."
    with pytest.raises(InvalidToken):
        decode_token(forged, expected_type="access")


def test_hs256_confusion_attack_rejected():
    """Classic RS256->HS256 downgrade attack: sign with HMAC using the
    (public, not secret) RSA public key as the HMAC secret, hoping a
    verifier that trusts the token's own `alg` header accepts it.
    Hand-built for the same reason as the alg=none test above -- jose's
    own encode() has a built-in guard against this exact construction."""
    import hashlib
    import hmac
    import json

    keys = signing_keys()
    public_pem = keys.public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    now = datetime.now(UTC)
    header = {"alg": "HS256", "kid": keys.kid, "typ": "JWT"}
    payload = {
        "iss": settings.JWT_ISSUER, "aud": settings.JWT_AUDIENCE, "sub": str(uuid.uuid4()),
        "type": "access", "jti": str(uuid.uuid4()),
        "iat": int(now.timestamp()), "exp": int((now + timedelta(minutes=5)).timestamp()),
    }
    signing_input = f"{_b64url(json.dumps(header).encode())}.{_b64url(json.dumps(payload).encode())}"
    signature = hmac.new(public_pem, signing_input.encode(), hashlib.sha256).digest()
    forged = f"{signing_input}.{_b64url(signature)}"
    with pytest.raises(InvalidToken):
        decode_token(forged, expected_type="access")
