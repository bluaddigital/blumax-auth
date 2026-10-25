"""MultiIssuerTokenVerifier -- a real dual-issuer trust anchor for a
service mid-migration between two token issuers. See its own docstring
in blumax_auth/verify.py for the full reasoning.
"""
from __future__ import annotations

import base64
import uuid
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import FastAPI
from jose import jwt

import blumax_auth
from blumax_auth import InvalidToken, JwksCache, MultiIssuerTokenVerifier, TokenVerifier, TrustAnchor

CORE_ISSUER = "https://core.blumax.test"
AUTH_ISSUER = "https://auth.blumax.test"
AUDIENCE = "blumax"


def _b64u(n: int) -> str:
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


class Signer:
    def __init__(self, issuer: str, kid: str) -> None:
        self.issuer = issuer
        self.kid = kid
        self._key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.pem = self._key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode()

    def jwks(self) -> dict:
        pub = self._key.public_key().public_numbers()
        return {"keys": [{
            "kty": "RSA", "use": "sig", "alg": "RS256", "kid": self.kid,
            "n": _b64u(pub.n), "e": _b64u(pub.e),
        }]}

    def token(self, **over) -> str:
        now = datetime.now(UTC)
        claims = {
            "iss": self.issuer, "aud": AUDIENCE, "sub": str(uuid.uuid4()),
            "type": "access", "jti": str(uuid.uuid4()),
            "iat": now, "exp": now + timedelta(minutes=10),
        }
        claims.update(over)
        return jwt.encode(claims, self.pem, algorithm="RS256", headers={"kid": self.kid})


@pytest.fixture
def core_signer() -> Signer:
    return Signer(CORE_ISSUER, "core-key-1")


@pytest.fixture
def auth_signer() -> Signer:
    return Signer(AUTH_ISSUER, "auth-key-1")


@pytest.fixture
def multi_verifier(core_signer: Signer, auth_signer: Signer) -> MultiIssuerTokenVerifier:
    core_cache = JwksCache("http://unused.invalid/core/jwks.json")
    core_cache.seed(core_signer.jwks())
    auth_cache = JwksCache("http://unused.invalid/auth/jwks.json")
    auth_cache.seed(auth_signer.jwks())
    return MultiIssuerTokenVerifier([
        TokenVerifier(core_cache, issuer=CORE_ISSUER, audience=AUDIENCE),
        TokenVerifier(auth_cache, issuer=AUTH_ISSUER, audience=AUDIENCE),
    ])


async def test_accepts_a_token_from_either_trusted_issuer(
    multi_verifier, core_signer, auth_signer
):
    core_ctx = await multi_verifier.verify(core_signer.token())
    auth_ctx = await multi_verifier.verify(auth_signer.token())
    assert core_ctx.user_id
    assert auth_ctx.user_id


async def test_refuses_an_untrusted_issuer(multi_verifier):
    rogue = Signer("https://not-trusted.example", "rogue-key")
    with pytest.raises(InvalidToken):
        await multi_verifier.verify(rogue.token())


async def test_a_forged_issuer_claim_does_not_bypass_signature_verification(
    multi_verifier, auth_signer
):
    """The routing peek at `iss` is not a trust decision: claiming the
    OTHER issuer's name while signing with your own key must still fail,
    not get routed to the wrong (and therefore non-matching) key set."""
    forged = auth_signer.token(iss=CORE_ISSUER)
    with pytest.raises(InvalidToken):
        await multi_verifier.verify(forged)


async def test_malformed_token_is_refused(multi_verifier):
    with pytest.raises(InvalidToken):
        await multi_verifier.verify("not-a-jwt-at-all")


async def test_requires_at_least_one_verifier():
    with pytest.raises(ValueError):
        MultiIssuerTokenVerifier([])


# ─── configure(also_trust=...) end-to-end ──────────────────────────────────

async def test_configure_without_also_trust_is_unchanged(core_signer: Signer):
    """Backward compatibility: every existing caller of configure() never
    passes also_trust, and must see zero behavior change."""
    blumax_auth.reset()
    blumax_auth.configure(
        jwks_url="http://unused.invalid/jwks.json", issuer=core_signer.issuer, audience=AUDIENCE,
    )
    blumax_auth.jwks_cache().seed(core_signer.jwks())

    app = FastAPI()

    @app.get("/open")
    async def open_route(ctx: blumax_auth.Auth) -> dict:
        return {"user_id": str(ctx.user_id)}

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as client:
        r = await client.get("/open", headers={"Authorization": f"Bearer {core_signer.token()}"})
        assert r.status_code == 200


async def test_configure_with_also_trust_accepts_both_issuers(core_signer: Signer, auth_signer: Signer):
    blumax_auth.reset()
    blumax_auth.configure(
        jwks_url="http://unused.invalid/core/jwks.json", issuer=core_signer.issuer, audience=AUDIENCE,
        also_trust=[TrustAnchor(
            jwks_url="http://unused.invalid/auth/jwks.json", issuer=auth_signer.issuer, audience=AUDIENCE,
        )],
    )
    # The primary cache is reachable via jwks_cache() as before; the
    # also_trust cache is seeded by constructing it the same way configure()
    # did -- not exposed as a public accessor (no existing consumer needs
    # to seed more than the primary in a real deployment, only this test).
    blumax_auth.jwks_cache().seed(core_signer.jwks())
    import blumax_auth.fastapi as fastapi_module
    fastapi_module._verifier._by_issuer[auth_signer.issuer]._jwks.seed(auth_signer.jwks())

    app = FastAPI()

    @app.get("/open")
    async def open_route(ctx: blumax_auth.Auth) -> dict:
        return {"user_id": str(ctx.user_id)}

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as client:
        r1 = await client.get("/open", headers={"Authorization": f"Bearer {core_signer.token()}"})
        assert r1.status_code == 200
        r2 = await client.get("/open", headers={"Authorization": f"Bearer {auth_signer.token()}"})
        assert r2.status_code == 200
