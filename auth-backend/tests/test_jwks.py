from __future__ import annotations

from httpx import AsyncClient

from app.core.keys import signing_keys


async def test_health_reports_all_three_dependencies(client: AsyncClient):
    """Phase 3C: health must distinguish DB/Redis/signing-key, never a
    blanket 200 when any of the three is actually unavailable."""
    r = await client.get("/health")
    assert r.status_code == 200
    body = r.json()
    assert body == {"status": "ok", "database": "ok", "redis": "ok", "signing_key": "ok"}


async def test_jwks_endpoint_returns_valid_jwk(client: AsyncClient):
    r = await client.get("/.well-known/jwks.json")
    assert r.status_code == 200
    body = r.json()
    assert "keys" in body
    assert len(body["keys"]) >= 1
    jwk = body["keys"][0]
    assert jwk["kty"] == "RSA"
    assert jwk["alg"] == "RS256"
    assert jwk["use"] == "sig"
    assert "n" in jwk and "e" in jwk


async def test_jwks_kid_matches_signing_key(client: AsyncClient):
    r = await client.get("/.well-known/jwks.json")
    body = r.json()
    assert body["keys"][0]["kid"] == signing_keys().kid


def test_multiple_keys_published_during_rotation(monkeypatch):
    """Simulates the rotation window: current key + one previous
    (verify-only) public key coexisting in JWKS, same mechanism as
    Core's own keys.py."""
    from cryptography.hazmat.primitives.asymmetric import rsa

    from app.core.keys import SigningKeys

    new_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    old_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    rotating = SigningKeys(new_key, old_key.public_key())

    jwks = rotating.jwks()
    assert len(jwks["keys"]) == 2
    kids = {k["kid"] for k in jwks["keys"]}
    assert len(kids) == 2  # distinct kids, no collision

    # Both the new key and the old (retiring) key can still be resolved
    # for verification purposes.
    assert rotating.key_for_kid(rotating.kid) is not None
    assert rotating.key_for_kid(rotating._previous_kid) is not None
    assert rotating.key_for_kid("totally-unknown") is None
