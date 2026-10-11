"""F2.0 — patient tokens and staff tokens never verify as each other.

Tokens are signed locally (as in test_verification.py) with the payload shapes
Core mints: staff `access`/`service`/`refresh` tokens for the `blumax` audience,
and `patient` tokens for the `blumax-patient` audience.
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
from blumax_auth import (
    Auth,
    InvalidToken,
    JwksCache,
    PatientAuth,
    PatientAuthContext,
    PatientTokenVerifier,
    TokenVerifier,
)

ISSUER = "https://core.blumax.test"
STAFF_AUD = "blumax"
PATIENT_AUD = "blumax-patient"


def _b64u(n: int) -> str:
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


class Signer:
    def __init__(self, kid: str = "core-key-1") -> None:
        self.kid = kid
        self._key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.pem = self._key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode()

    def jwks(self) -> dict:
        pub = self._key.public_key().public_numbers()
        return {"keys": [{"kty": "RSA", "use": "sig", "alg": "RS256", "kid": self.kid,
                          "n": _b64u(pub.n), "e": _b64u(pub.e)}]}

    def _sign(self, claims: dict, kid: str | None = None) -> str:
        return jwt.encode(claims, self.pem, algorithm="RS256", headers={"kid": kid or self.kid})

    def patient(self, drop: tuple[str, ...] = (), kid: str | None = None, **over) -> str:
        now = datetime.now(UTC)
        claims = {
            "iss": ISSUER, "aud": PATIENT_AUD, "type": "patient",
            "sub": str(uuid.uuid4()), "gpid": str(uuid.uuid4()), "sid": str(uuid.uuid4()),
            "jti": str(uuid.uuid4()), "amr": ["otp"],
            "iat": now, "exp": now + timedelta(minutes=15),
        }
        claims.update(over)
        for k in drop:
            claims.pop(k, None)
        return self._sign(claims, kid)

    def staff(self, **over) -> str:
        now = datetime.now(UTC)
        claims = {
            "iss": ISSUER, "aud": STAFF_AUD, "sub": str(uuid.uuid4()), "type": "access",
            "jti": str(uuid.uuid4()), "iat": now, "exp": now + timedelta(minutes=10),
            "tid": str(uuid.uuid4()), "tsl": "apollo", "rol": "CLINICIAN", "arc": "CLINICIAN",
            "fac": None, "pid": None, "prv": None, "adm": False,
        }
        claims.update(over)
        return self._sign(claims)


@pytest.fixture
def signer() -> Signer:
    return Signer()


def _cache(*signers: Signer) -> JwksCache:
    cache = JwksCache("http://unused.invalid/jwks.json")
    cache.seed({"keys": [k for s in signers for k in s.jwks()["keys"]]})
    return cache


@pytest.fixture
def patient_verifier(signer) -> PatientTokenVerifier:
    return PatientTokenVerifier(_cache(signer), issuer=ISSUER, audience=PATIENT_AUD)


@pytest.fixture
def staff_verifier(signer) -> TokenVerifier:
    return TokenVerifier(_cache(signer), issuer=ISSUER, audience=STAFF_AUD)


# ─── The patient verifier ─────────────────────────────────────────────────────

class TestPatientVerifier:

    async def test_accepts_a_patient_token_and_maps_its_claims(self, signer, patient_verifier):
        acc, gp, sid = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
        ctx = await patient_verifier.verify(signer.patient(sub=str(acc), gpid=str(gp), sid=str(sid)))
        assert isinstance(ctx, PatientAuthContext)
        assert (ctx.account_id, ctx.global_person_id, ctx.session_id) == (acc, gp, sid)
        assert ctx.jti and ctx.issued_at is not None

    @pytest.mark.parametrize("token_type", ["access", "service", "refresh", None, "PATIENT"])
    async def test_rejects_any_other_type_even_for_the_patient_audience(
        self, signer, patient_verifier, token_type
    ):
        with pytest.raises(InvalidToken):
            await patient_verifier.verify(signer.patient(type=token_type))

    @pytest.mark.parametrize("token_type", ["access", "service", "refresh"])
    async def test_rejects_staff_tokens(self, signer, patient_verifier, token_type):
        with pytest.raises(InvalidToken):
            await patient_verifier.verify(signer.staff(type=token_type))

    @pytest.mark.parametrize("claim,value", [
        ("tid", str(uuid.uuid4())), ("tsl", "apollo"), ("rol", "CLINICIAN"), ("arc", "VIEWER"),
        ("fac", []), ("pid", str(uuid.uuid4())), ("prv", str(uuid.uuid4())), ("adm", True),
        ("snm", "svc"),
    ])
    async def test_rejects_a_patient_token_carrying_any_staff_claim(
        self, signer, patient_verifier, claim, value
    ):
        with pytest.raises(InvalidToken):
            await patient_verifier.verify(signer.patient(**{claim: value}))

    @pytest.mark.parametrize("missing", ["sub", "gpid", "sid", "jti"])
    async def test_rejects_missing_required_claims(self, signer, patient_verifier, missing):
        with pytest.raises(InvalidToken):
            await patient_verifier.verify(signer.patient(drop=(missing,)))

    @pytest.mark.parametrize("claim", ["sub", "gpid", "sid"])
    async def test_rejects_non_uuid_identifiers(self, signer, patient_verifier, claim):
        with pytest.raises(InvalidToken):
            await patient_verifier.verify(signer.patient(**{claim: "not-a-uuid"}))

    async def test_rejects_wrong_audience(self, signer, patient_verifier):
        with pytest.raises(InvalidToken):
            await patient_verifier.verify(signer.patient(aud=STAFF_AUD))

    async def test_rejects_wrong_issuer(self, signer, patient_verifier):
        with pytest.raises(InvalidToken):
            await patient_verifier.verify(signer.patient(iss="https://evil.example"))

    async def test_rejects_expired(self, signer, patient_verifier):
        past = datetime.now(UTC) - timedelta(hours=1)
        with pytest.raises(InvalidToken):
            await patient_verifier.verify(signer.patient(iat=past - timedelta(minutes=15), exp=past))

    async def test_rejects_a_forged_signature(self, patient_verifier):
        forger = Signer(kid="core-key-1")   # same kid, different private key
        with pytest.raises(InvalidToken):
            await patient_verifier.verify(forger.patient())

    async def test_rejects_alg_none_and_hs256(self, signer, patient_verifier):
        now = datetime.now(UTC)
        claims = {"iss": ISSUER, "aud": PATIENT_AUD, "type": "patient", "sub": str(uuid.uuid4()),
                  "gpid": str(uuid.uuid4()), "sid": str(uuid.uuid4()), "jti": "j",
                  "iat": now, "exp": now + timedelta(minutes=5)}
        hs = jwt.encode(claims, "shared-secret", algorithm="HS256", headers={"kid": signer.kid})
        unsigned = (base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').rstrip(b"=").decode()
                    + "." + hs.split(".")[1] + ".")
        for token in (hs, unsigned):
            with pytest.raises(InvalidToken):
                await patient_verifier.verify(token)

    def test_refuses_to_construct_without_an_audience(self, signer):
        with pytest.raises(ValueError):
            PatientTokenVerifier(_cache(signer), issuer=ISSUER, audience="")


# ─── The staff verifier is unchanged and refuses patient tokens ──────────────

class TestStaffVerifierRejectsPatients:

    async def test_patient_token_for_patient_audience_is_rejected(self, signer, staff_verifier):
        with pytest.raises(InvalidToken):
            await staff_verifier.verify(signer.patient())

    async def test_patient_type_is_rejected_even_with_the_staff_audience(self, signer, staff_verifier):
        with pytest.raises(InvalidToken):
            await staff_verifier.verify(signer.patient(aud=STAFF_AUD))

    async def test_staff_access_token_still_verifies(self, signer, staff_verifier):
        assert (await staff_verifier.verify(signer.staff())).tenant_id is not None


# ─── FastAPI: require_patient fails closed on the session ───────────────────

def _app(signer: Signer, checker) -> FastAPI:
    blumax_auth.reset()
    blumax_auth.reset_patients()
    blumax_auth.configure(jwks_url="http://unused.invalid/jwks.json", issuer=ISSUER, audience=STAFF_AUD)
    blumax_auth.jwks_cache().seed(signer.jwks())
    blumax_auth.configure_patients(
        jwks_url="http://unused.invalid/jwks.json", issuer=ISSUER, audience=PATIENT_AUD,
        session_checker=checker,
    )
    blumax_auth.patient_jwks_cache().seed(signer.jwks())

    app = FastAPI()
    blumax_auth.install_error_handler(app)

    @app.get("/me")
    async def me(ctx: PatientAuth) -> dict:
        return {"account": str(ctx.account_id)}

    @app.get("/staff")
    async def staff(ctx: Auth) -> dict:
        return {"user": str(ctx.user_id)}

    return app


async def _get(app: FastAPI, path: str, token: str | None) -> httpx.Response:
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as c:
        return await c.get(path, headers=headers)


async def _active(ctx, token) -> bool:
    return True


class TestRequirePatient:

    @pytest.fixture(autouse=True)
    def _clean(self):
        yield
        blumax_auth.reset()
        blumax_auth.reset_patients()

    async def test_active_session_is_admitted(self, signer):
        acc = uuid.uuid4()
        r = await _get(_app(signer, _active), "/me", signer.patient(sub=str(acc)))
        assert r.status_code == 200 and r.json() == {"account": str(acc)}

    async def test_checker_receives_the_verified_context(self, signer):
        seen = []

        async def checker(ctx, token):
            seen.append((ctx, token))
            return True

        sid = uuid.uuid4()
        token = signer.patient(sid=str(sid))
        await _get(_app(signer, checker), "/me", token)
        assert [(c.session_id, t) for c, t in seen] == [(sid, token)]

    async def test_inactive_session_is_401(self, signer):
        async def revoked(ctx, token):
            return False

        r = await _get(_app(signer, revoked), "/me", signer.patient())
        assert r.status_code == 401

    @pytest.mark.parametrize("answer", [None, 1, "yes"])
    async def test_anything_but_true_is_refused(self, signer, answer):
        async def odd(ctx, token):
            return answer

        r = await _get(_app(signer, odd), "/me", signer.patient())
        assert r.status_code == 401

    async def test_unanswerable_session_check_fails_closed_503(self, signer):
        async def down(ctx, token):
            raise ConnectionError("redis down")

        r = await _get(_app(signer, down), "/me", signer.patient())
        assert r.status_code == 503
        assert r.json()["error"]["code"] == "SESSION_CHECK_UNAVAILABLE"

    async def test_checker_is_not_called_for_an_invalid_token(self, signer):
        calls = []

        async def checker(ctx, token):
            calls.append(ctx)
            return True

        r = await _get(_app(signer, checker), "/me", signer.staff())
        assert r.status_code == 401 and calls == []

    async def test_no_credentials_is_401(self, signer):
        assert (await _get(_app(signer, _active), "/me", None)).status_code == 401

    async def test_patient_token_on_a_staff_route_is_401(self, signer):
        assert (await _get(_app(signer, _active), "/staff", signer.patient())).status_code == 401

    async def test_staff_token_on_a_patient_route_is_401(self, signer):
        for t in ("access", "service", "refresh"):
            r = await _get(_app(signer, _active), "/me", signer.staff(type=t))
            assert r.status_code == 401, t

    def test_configuring_without_a_session_checker_is_refused(self, signer):
        with pytest.raises(ValueError):
            blumax_auth.configure_patients(
                jwks_url="http://unused.invalid/jwks.json", issuer=ISSUER, audience=PATIENT_AUD,
                session_checker=None,  # type: ignore[arg-type]
            )

    async def test_unconfigured_patient_path_does_not_admit_anyone(self, signer):
        blumax_auth.reset_patients()
        app = FastAPI()

        @app.get("/me")
        async def me(ctx: PatientAuth) -> dict:
            return {}

        with pytest.raises(RuntimeError):
            await _get(app, "/me", signer.patient())


# ─── core_session_checker: forwards the bearer to Core, fails closed ─────────

class TestCoreSessionChecker:

    def _checker(self, status=None, exc=None, seen=None):
        def handler(request: httpx.Request) -> httpx.Response:
            if seen is not None:
                seen.append(request)
            if exc is not None:
                raise exc
            return httpx.Response(status)
        return blumax_auth.core_session_checker(
            "http://core.test/", transport=httpx.MockTransport(handler)
        )

    async def test_forwards_the_patients_own_bearer_to_core(self, signer):
        seen = []
        token = signer.patient()
        ctx = await PatientTokenVerifier(_cache(signer), issuer=ISSUER, audience=PATIENT_AUD).verify(token)
        assert await self._checker(200, seen=seen)(ctx, token) is True
        assert len(seen) == 1
        assert str(seen[0].url) == "http://core.test/api/v1/patient-auth/session"
        assert seen[0].headers["Authorization"] == f"Bearer {token}"

    @pytest.mark.parametrize("status", [401, 403])
    async def test_core_saying_no_is_inactive(self, signer, status):
        assert await self._checker(status)(None, signer.patient()) is False

    @pytest.mark.parametrize("status", [500, 502, 503, 404, 302, 204])
    async def test_anything_else_raises_so_the_request_fails_closed(self, signer, status):
        with pytest.raises(RuntimeError):
            await self._checker(status)(None, signer.patient())

    async def test_unreachable_core_raises(self, signer):
        with pytest.raises(httpx.ConnectError):
            await self._checker(exc=httpx.ConnectError("down"))(None, signer.patient())

    async def test_end_to_end_unreachable_core_is_503_on_a_patient_route(self, signer):
        def handler(request):
            raise httpx.ConnectError("down")
        checker = blumax_auth.core_session_checker(
            "http://core.test", transport=httpx.MockTransport(handler)
        )
        try:
            r = await _get(_app(signer, checker), "/me", signer.patient())
        finally:
            blumax_auth.reset()
            blumax_auth.reset_patients()
        assert r.status_code == 503
