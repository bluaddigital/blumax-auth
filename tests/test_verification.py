"""blumax-auth verification contract.

Tokens are signed here with a locally generated RSA key rather than by calling
Core, so the package can be tested standalone — but the payload shape is
exactly what app/core/security.py mints. That correspondence is pinned from the
other side too, by test_issuer_contract.py in Core's own suite, which mints a
real token and verifies it through this package.
"""
from __future__ import annotations

import base64
import json
import uuid
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import FastAPI
from jose import jwt

import blumax_auth
from blumax_auth import (
    AuthContext,
    InvalidToken,
    JwksCache,
    TokenVerifier,
)

ISSUER = "https://core.blumax.test"
AUDIENCE = "blumax"


# ─── Key fixtures ─────────────────────────────────────────────────────────────

def _b64u(n: int) -> str:
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


class Signer:
    """A stand-in for Core: holds a private key and publishes its JWKS."""

    def __init__(self, kid: str = "test-key-1") -> None:
        self.kid = kid
        self._key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.pem = self._key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode()

    def jwks(self) -> dict:
        pub = self._key.public_key().public_numbers()
        return {
            "keys": [
                {
                    "kty": "RSA", "use": "sig", "alg": "RS256", "kid": self.kid,
                    "n": _b64u(pub.n), "e": _b64u(pub.e),
                }
            ]
        }

    def token(self, **over) -> str:
        now = datetime.now(UTC)
        claims = {
            "iss": ISSUER, "aud": AUDIENCE, "sub": str(uuid.uuid4()),
            "type": "access", "jti": str(uuid.uuid4()),
            "iat": now, "exp": now + timedelta(minutes=10),
            "tid": str(uuid.uuid4()), "tsl": "apollo", "rol": "CLINICIAN",
            "arc": "CLINICIAN",
            "fac": None, "pid": None, "prv": None, "adm": False,
        }
        claims.update(over)
        alg = over.pop("_alg", "RS256")
        return jwt.encode(claims, self.pem, algorithm=alg, headers={"kid": self.kid})


@pytest.fixture
def signer() -> Signer:
    return Signer()


@pytest.fixture
def verifier(signer: Signer) -> TokenVerifier:
    cache = JwksCache("http://unused.invalid/jwks.json")
    cache.seed(signer.jwks())
    return TokenVerifier(cache, issuer=ISSUER, audience=AUDIENCE)


# ─── Happy path ───────────────────────────────────────────────────────────────

class TestValidTokens:

    async def test_verifies_and_maps_every_claim(self, signer, verifier):
        uid, tid, fid, pid, prv = (uuid.uuid4() for _ in range(5))
        token = signer.token(
            sub=str(uid), tid=str(tid), tsl="apollo", rol="CLINICIAN",
            fac=[str(fid)], pid=str(pid), prv=str(prv), adm=False,
        )
        ctx = await verifier.verify(token)
        assert isinstance(ctx, AuthContext)
        assert ctx.user_id == uid
        assert ctx.tenant_id == tid
        assert ctx.tenant_slug == "apollo"
        assert ctx.role == "CLINICIAN"
        assert ctx.facility_ids == frozenset({fid})
        assert ctx.person_id == pid
        assert ctx.provider_id == prv
        assert ctx.is_platform_admin is False
        assert ctx.jti

    async def test_null_facilities_means_unrestricted(self, signer, verifier):
        ctx = await verifier.verify(signer.token(fac=None))
        assert ctx.facility_ids is None
        assert ctx.may_access_facility(uuid.uuid4()) is True

    async def test_empty_facilities_means_none(self, signer, verifier):
        """The distinction the old frozenset()-means-everything code lost."""
        ctx = await verifier.verify(signer.token(fac=[]))
        assert ctx.facility_ids == frozenset()
        assert ctx.may_access_facility(uuid.uuid4()) is False

    async def test_tenant_less_token_verifies(self, signer, verifier):
        """Platform admins hold one. Authentication succeeds; require_tenant
        is what refuses it."""
        ctx = await verifier.verify(signer.token(tid=None, adm=True))
        assert ctx.tenant_id is None
        assert ctx.is_platform_admin is True

    async def test_small_clock_skew_is_tolerated(self, signer, verifier):
        """Core and this service run on different hosts; a few seconds of
        drift must not 401 someone mid-round."""
        now = datetime.now(UTC)
        ctx = await verifier.verify(
            signer.token(iat=now + timedelta(seconds=10), exp=now + timedelta(minutes=5))
        )
        assert ctx.user_id

    async def test_access_token_is_not_flagged_as_service(self, signer, verifier):
        ctx = await verifier.verify(signer.token(type="access"))
        assert ctx.is_service is False

    async def test_service_token_verifies_and_is_flagged(self, signer, verifier):
        """A service-account (client-credentials) caller acting on a tenant's
        behalf — e.g. one service calling another cross-service — carries the
        exact same claim shape as a human session except `type`. It must
        verify identically (same tid/rol/arc/sub handling) rather than being
        blanket-rejected the way a genuinely wrong type ("refresh", tested in
        TestRejection) is."""
        ctx = await verifier.verify(signer.token(type="service"))
        assert ctx.is_service is True
        assert ctx.user_id
        assert ctx.tenant_id


# ─── Rejection ────────────────────────────────────────────────────────────────

class TestRejection:

    @pytest.mark.parametrize(
        ("label", "over"),
        [
            ("wrong audience", {"aud": "another-platform"}),
            ("wrong issuer", {"iss": "https://evil.example"}),
            ("refresh used as access", {"type": "refresh"}),
            ("no subject", {"sub": None}),
            ("malformed facility list", {"fac": ["not-a-uuid"]}),
            ("non-uuid tenant", {"tid": "tenant-one"}),
        ],
    )
    async def test_rejected(self, signer, verifier, label, over):
        with pytest.raises(InvalidToken):
            await verifier.verify(signer.token(**over))

    async def test_expired_beyond_leeway(self, signer, verifier):
        now = datetime.now(UTC)
        with pytest.raises(InvalidToken):
            await verifier.verify(
                signer.token(iat=now - timedelta(hours=2), exp=now - timedelta(hours=1))
            )

    async def test_signed_by_a_different_key(self, signer, verifier):
        """The property a shared secret cannot give: holding the public key
        does not let you mint."""
        attacker = Signer(kid=signer.kid)  # same kid, different key
        with pytest.raises(InvalidToken):
            await verifier.verify(attacker.token())

    async def test_tampered_payload(self, signer, verifier):
        token = signer.token(adm=False)
        head, payload, sig = token.split(".")
        claims = json.loads(base64.urlsafe_b64decode(payload + "=="))
        claims["adm"] = True
        forged = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=").decode()
        with pytest.raises(InvalidToken):
            await verifier.verify(f"{head}.{forged}.{sig}")

    async def test_hs256_algorithm_confusion_is_refused(self, signer, verifier):
        """Classic attack: set alg to HS256 and HMAC with the PUBLIC key, hoping
        the verifier reads alg from the header and treats the key it already
        holds as a shared secret.

        Hand-assembled rather than built with jose, which refuses to HMAC with
        an asymmetric key — an attacker has no such scruples.
        """
        import hashlib
        import hmac

        pub_pem = (
            serialization.load_pem_private_key(signer.pem.encode(), password=None)
            .public_key()
            .public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
        header = base64.urlsafe_b64encode(
            json.dumps({"alg": "HS256", "typ": "JWT", "kid": signer.kid}).encode()
        ).rstrip(b"=")
        payload = base64.urlsafe_b64encode(
            json.dumps({
                "iss": ISSUER, "aud": AUDIENCE, "sub": str(uuid.uuid4()),
                "type": "access", "adm": True, "exp": 9999999999,
            }).encode()
        ).rstrip(b"=")
        sig = base64.urlsafe_b64encode(
            hmac.new(pub_pem, header + b"." + payload, hashlib.sha256).digest()
        ).rstrip(b"=")
        forged = b".".join([header, payload, sig]).decode()

        with pytest.raises(InvalidToken):
            await verifier.verify(forged)

    async def test_none_algorithm_is_refused(self, signer, verifier):
        header = base64.urlsafe_b64encode(
            json.dumps({"alg": "none", "typ": "JWT", "kid": signer.kid}).encode()
        ).rstrip(b"=").decode()
        payload = base64.urlsafe_b64encode(
            json.dumps({"iss": ISSUER, "aud": AUDIENCE, "sub": str(uuid.uuid4()),
                        "type": "access", "adm": True,
                        "exp": 9999999999}).encode()
        ).rstrip(b"=").decode()
        with pytest.raises(InvalidToken):
            await verifier.verify(f"{header}.{payload}.")

    async def test_garbage_is_refused(self, verifier):
        with pytest.raises(InvalidToken):
            await verifier.verify("not.a.token")

    async def test_unknown_kid_is_refused(self, signer):
        cache = JwksCache("http://unreachable.invalid/jwks.json")
        cache.seed(signer.jwks())
        v = TokenVerifier(cache, issuer=ISSUER, audience=AUDIENCE)
        other = Signer(kid="some-other-key")
        with pytest.raises(InvalidToken):
            await v.verify(other.token())


# ─── JWKS cache ───────────────────────────────────────────────────────────────

class TestJwksCache:

    async def test_fetches_over_http(self, signer):
        calls = {"n": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            calls["n"] += 1
            return httpx.Response(200, json=signer.jwks())

        transport = httpx.MockTransport(handler)
        cache = JwksCache("http://core.test/.well-known/jwks.json")

        real = httpx.AsyncClient
        httpx.AsyncClient = lambda **kw: real(transport=transport, **kw)  # type: ignore[assignment]
        try:
            key = await cache.get_key(signer.kid)
            assert key["kid"] == signer.kid
            # Second lookup is served from cache — verification stays CPU-only.
            await cache.get_key(signer.kid)
            assert calls["n"] == 1
        finally:
            httpx.AsyncClient = real  # type: ignore[assignment]

    async def test_serves_stale_keys_when_core_is_unreachable(self, signer):
        """Core being down must not stop a ward from authenticating."""
        cache = JwksCache("http://unreachable.invalid:1/jwks.json", ttl_seconds=0)
        cache.seed(signer.jwks())
        key = await cache.get_key(signer.kid)
        assert key["kid"] == signer.kid

    async def test_cold_cache_and_unreachable_core_fails_closed(self):
        """With no key ever seen there is nothing to verify against, so the
        only safe answer is refusal."""
        cache = JwksCache("http://unreachable.invalid:1/jwks.json")
        with pytest.raises(InvalidToken):
            await cache.get_key("any-kid")

    async def test_rotation_picks_up_a_new_key(self, signer):
        """A kid the cache has not seen triggers exactly one refetch — which is
        what lets Core rotate without restarting every service."""
        rotated = Signer(kid="rotated-key")
        served = {"jwks": signer.jwks()}

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json=served["jwks"])

        transport = httpx.MockTransport(handler)
        cache = JwksCache("http://core.test/jwks.json", min_refetch_interval=0)
        real = httpx.AsyncClient
        httpx.AsyncClient = lambda **kw: real(transport=transport, **kw)  # type: ignore[assignment]
        try:
            await cache.get_key(signer.kid)
            served["jwks"] = {"keys": signer.jwks()["keys"] + rotated.jwks()["keys"]}
            key = await cache.get_key(rotated.kid)
            assert key["kid"] == rotated.kid
        finally:
            httpx.AsyncClient = real  # type: ignore[assignment]

    async def test_missing_kid_resolves_only_when_unambiguous(self, signer):
        cache = JwksCache("http://unused.invalid/jwks.json")
        cache.seed(signer.jwks())
        assert (await cache.get_key(None))["kid"] == signer.kid

        two = {"keys": signer.jwks()["keys"] + Signer(kid="second").jwks()["keys"]}
        cache.seed(two)
        with pytest.raises(InvalidToken):
            # Two published keys and no kid: guessing would mean accepting a
            # token we cannot attribute to a key.
            await cache.get_key(None)


# ─── FastAPI dependencies ─────────────────────────────────────────────────────

@pytest.fixture
def app(signer: Signer) -> FastAPI:
    blumax_auth.reset()
    blumax_auth.configure(
        jwks_url="http://unused.invalid/jwks.json", issuer=ISSUER, audience=AUDIENCE
    )
    blumax_auth.jwks_cache().seed(signer.jwks())

    application = FastAPI()
    blumax_auth.install_error_handler(application)

    @application.get("/open")
    async def open_route(ctx: blumax_auth.Auth) -> dict:
        return {"user_id": str(ctx.user_id)}

    @application.get("/scoped")
    async def scoped(ctx: blumax_auth.TenantAuth) -> dict:
        return {"tenant_id": str(ctx.tenant_id)}

    from fastapi import Depends

    @application.get("/clinicians-only")
    async def clinicians(
        ctx: AuthContext = Depends(blumax_auth.require_role("CLINICIAN")),
    ) -> dict:
        return {"role": ctx.role}

    @application.get("/clinical-archetype")
    async def clinical_archetype(
        ctx: AuthContext = Depends(blumax_auth.require_archetype("CLINICIAN")),
    ) -> dict:
        return {"role": ctx.role, "archetype": ctx.archetype}

    return application


@pytest.fixture
async def client(app: FastAPI):
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://t"
    ) as c:
        yield c


class TestDependencies:

    async def test_valid_token_is_accepted(self, client, signer):
        r = await client.get(
            "/scoped", headers={"Authorization": f"Bearer {signer.token()}"}
        )
        assert r.status_code == 200

    async def test_no_header_is_401(self, client):
        r = await client.get("/scoped")
        assert r.status_code == 401
        assert r.json()["error"]["code"] == "AUTHENTICATION_FAILED"

    async def test_errors_use_the_shared_envelope(self, client):
        """Not FastAPI's {"detail": ...} — the services' contract tests assert
        this shape for every error."""
        body = (await client.get("/scoped")).json()
        assert set(body) == {"error"}
        assert set(body["error"]) == {"code", "message", "details"}

    async def test_tenant_less_token_is_400_on_a_tenant_route(self, client, signer):
        r = await client.get(
            "/scoped", headers={"Authorization": f"Bearer {signer.token(tid=None)}"}
        )
        assert r.status_code == 400
        assert r.json()["error"]["code"] == "TENANT_CONTEXT_MISSING"

    async def test_tenant_less_token_still_authenticates(self, client, signer):
        r = await client.get(
            "/open", headers={"Authorization": f"Bearer {signer.token(tid=None)}"}
        )
        assert r.status_code == 200

    async def test_matching_tenant_header_is_accepted(self, client, signer):
        tid = str(uuid.uuid4())
        r = await client.get(
            "/scoped",
            headers={"Authorization": f"Bearer {signer.token(tid=tid)}",
                     "X-Tenant-ID": tid},
        )
        assert r.status_code == 200

    async def test_mismatched_tenant_header_is_403(self, client, signer):
        """The header can never select the tenant. This is the assertion that
        makes cross-tenant isolation provable."""
        r = await client.get(
            "/scoped",
            headers={"Authorization": f"Bearer {signer.token(tid=str(uuid.uuid4()))}",
                     "X-Tenant-ID": str(uuid.uuid4())},
        )
        assert r.status_code == 403
        assert r.json()["error"]["code"] == "TENANT_ACCESS_DENIED"

    async def test_role_gate_allows_the_role(self, client, signer):
        r = await client.get(
            "/clinicians-only",
            headers={"Authorization": f"Bearer {signer.token(rol='CLINICIAN')}"},
        )
        assert r.status_code == 200

    async def test_role_gate_refuses_another_role(self, client, signer):
        r = await client.get(
            "/clinicians-only",
            headers={
                "Authorization": f"Bearer {signer.token(rol='VIEWER', arc='VIEWER')}"
            },
        )
        assert r.status_code == 403

    async def test_platform_admin_passes_any_role_gate(self, client, signer):
        r = await client.get(
            "/clinicians-only",
            headers={"Authorization": f"Bearer {signer.token(rol='VIEWER', adm=True)}"},
        )
        assert r.status_code == 200

    async def test_forged_token_is_401(self, client):
        attacker = Signer()
        r = await client.get(
            "/scoped", headers={"Authorization": f"Bearer {attacker.token()}"}
        )
        assert r.status_code == 401

    async def test_service_token_reaches_a_tenant_scoped_route(self, client, signer):
        """The exact cross-service scenario this claim shape exists for: one
        service authenticating to another with a service-account token, not
        a human session. Must pass TenantAuth the same way an access token
        does — a service-account caller still carries a real tid."""
        r = await client.get(
            "/scoped", headers={"Authorization": f"Bearer {signer.token(type='service')}"}
        )
        assert r.status_code == 200


# ─── Archetypes ───────────────────────────────────────────────────────────────
#
# The reason this claim exists: hospitals name their own roles, and this
# service will never hear those names.

class TestArchetype:

    async def test_maps_the_claim(self, signer, verifier):
        ctx = await verifier.verify(signer.token(rol="Senior Registrar", arc="CLINICIAN"))
        assert ctx.role == "Senior Registrar"
        assert ctx.archetype == "CLINICIAN"

    async def test_a_token_without_the_claim_gets_the_least_access(
        self, signer, verifier
    ):
        # A token minted before `arc` existed must not be read as an admin.
        ctx = await verifier.verify(signer.token(arc=None))
        assert ctx.archetype == "VIEWER"

    async def test_missing_claim_entirely_is_also_viewer(self, signer, verifier):
        # Rebuild without the key rather than setting it to None, so the
        # absent-key path is covered too — a token minted by a Core that
        # predates this claim has no `arc` at all.
        raw = jwt.get_unverified_claims(signer.token())
        raw.pop("arc")
        token = jwt.encode(
            raw, signer.pem, algorithm="RS256", headers={"kid": signer.kid}
        )
        assert (await verifier.verify(token)).archetype == "VIEWER"

    async def test_a_hospital_named_role_reaches_a_clinician_route(
        self, client, signer
    ):
        # The lockout this claim prevents: the route names CLINICIAN, the
        # caller's role is a name this service has never seen.
        r = await client.get(
            "/clinicians-only",
            headers={"Authorization": f"Bearer {signer.token(rol='Duty MO', arc='CLINICIAN')}"},
        )
        assert r.status_code == 200
        assert r.json()["role"] == "Duty MO"

    async def test_require_role_still_refuses_a_different_archetype(
        self, client, signer
    ):
        r = await client.get(
            "/clinicians-only",
            headers={"Authorization": f"Bearer {signer.token(rol='Front Desk', arc='VIEWER')}"},
        )
        assert r.status_code == 403

    async def test_require_archetype_ignores_the_role_name(self, client, signer):
        r = await client.get(
            "/clinical-archetype",
            headers={"Authorization": f"Bearer {signer.token(rol='Anything', arc='CLINICIAN')}"},
        )
        assert r.status_code == 200

    async def test_require_archetype_refuses_a_matching_name_with_wrong_archetype(
        self, client, signer
    ):
        # A hospital calling a receptionist role "CLINICIAN" must not get
        # clinical access from the name alone.
        r = await client.get(
            "/clinical-archetype",
            headers={"Authorization": f"Bearer {signer.token(rol='CLINICIAN', arc='VIEWER')}"},
        )
        assert r.status_code == 403

    async def test_platform_admin_passes_an_archetype_gate(self, client, signer):
        r = await client.get(
            "/clinical-archetype",
            headers={"Authorization": f"Bearer {signer.token(arc='VIEWER', adm=True)}"},
        )
        assert r.status_code == 200
