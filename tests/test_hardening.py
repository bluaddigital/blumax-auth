"""Hardening: required claims, JWKS max stale age, session-revocation fail_mode."""
from __future__ import annotations

import logging
import time
import uuid
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from fastapi import Depends, FastAPI
from jose import jwt
from test_session_revocation import LOGGER, FakeRedis, _configure
from test_verification import AUDIENCE, ISSUER, Signer

import blumax_auth
from blumax_auth import InvalidToken, JwksCache, TokenVerifier
from blumax_auth.session_revocation import check_session_revocation

# ─── required claims ──────────────────────────────────────────────────────────

def _token_without(signer: Signer, missing: str) -> str:
    now = datetime.now(UTC)
    claims = {
        "iss": ISSUER, "aud": AUDIENCE, "sub": str(uuid.uuid4()), "type": "access",
        "jti": str(uuid.uuid4()), "iat": now, "exp": now + timedelta(minutes=10),
    }
    del claims[missing]
    return jwt.encode(claims, signer.pem, algorithm="RS256", headers={"kid": signer.kid})


@pytest.fixture
def signer() -> Signer:
    return Signer()


@pytest.fixture
def verifier(signer: Signer) -> TokenVerifier:
    cache = JwksCache("http://unused.invalid/jwks.json")
    cache.seed(signer.jwks())
    return TokenVerifier(cache, issuer=ISSUER, audience=AUDIENCE)


class TestRequiredClaims:
    @pytest.mark.parametrize("missing", ["exp", "aud", "iat"])
    async def test_token_missing_claim_is_rejected(self, signer, verifier, missing):
        with pytest.raises(InvalidToken):
            await verifier.verify(_token_without(signer, missing))

    async def test_complete_token_still_verifies(self, signer, verifier):
        ctx = await verifier.verify(signer.token())
        assert ctx.issued_at is not None

    async def test_leeway_still_applies(self, signer, verifier):
        just_expired = datetime.now(UTC) - timedelta(seconds=10)
        assert await verifier.verify(signer.token(exp=just_expired))
        long_expired = datetime.now(UTC) - timedelta(seconds=120)
        with pytest.raises(InvalidToken):
            await verifier.verify(signer.token(exp=long_expired))


# ─── JWKS max stale age ───────────────────────────────────────────────────────

class TestJwksMaxStale:
    def _age(self, cache: JwksCache, seconds: float) -> None:
        cache._fetched_at = time.monotonic() - seconds

    async def test_default_is_24h_and_stale_within_bound_still_served(self, signer):
        cache = JwksCache("http://unreachable.invalid:1/jwks.json")
        assert cache._max_stale == 24 * 3600
        cache.seed(signer.jwks())
        self._age(cache, 23 * 3600)  # past the 1h TTL, inside the bound
        assert (await cache.get_key(signer.kid))["kid"] == signer.kid

    async def test_beyond_bound_with_core_down_fails_closed(self, signer):
        cache = JwksCache("http://unreachable.invalid:1/jwks.json")
        cache.seed(signer.jwks())
        self._age(cache, 25 * 3600)
        with pytest.raises(InvalidToken, match="stale"):
            await cache.get_key(signer.kid)

    async def test_custom_arg_bound(self, signer):
        cache = JwksCache("http://unreachable.invalid:1/jwks.json", max_stale_seconds=60)
        cache.seed(signer.jwks())
        self._age(cache, 120)
        with pytest.raises(InvalidToken):
            await cache.get_key(signer.kid)

    async def test_zero_disables_bound(self, signer):
        cache = JwksCache("http://unreachable.invalid:1/jwks.json", max_stale_seconds=0)
        cache.seed(signer.jwks())
        self._age(cache, 10 * 24 * 3600)
        assert (await cache.get_key(signer.kid))["kid"] == signer.kid

    async def test_env_configures_bound(self, signer, monkeypatch):
        monkeypatch.setenv("BLUMAX_AUTH_JWKS_MAX_STALE_SECONDS", "30")
        cache = JwksCache("http://unreachable.invalid:1/jwks.json")
        cache.seed(signer.jwks())
        self._age(cache, 60)
        with pytest.raises(InvalidToken):
            await cache.get_key(signer.kid)

    def test_invalid_env_or_negative_raises(self, monkeypatch):
        monkeypatch.setenv("BLUMAX_AUTH_JWKS_MAX_STALE_SECONDS", "abc")
        with pytest.raises(ValueError):
            JwksCache("http://x.invalid/jwks.json")
        monkeypatch.delenv("BLUMAX_AUTH_JWKS_MAX_STALE_SECONDS")
        with pytest.raises(ValueError):
            JwksCache("http://x.invalid/jwks.json", max_stale_seconds=-1)

    async def test_successful_refresh_recovers(self, signer):
        transport = httpx.MockTransport(lambda r: httpx.Response(200, json=signer.jwks()))
        cache = JwksCache("http://core.test/jwks.json")
        cache.seed(signer.jwks())
        self._age(cache, 48 * 3600)
        real = httpx.AsyncClient
        httpx.AsyncClient = lambda **kw: real(transport=transport, **kw)  # type: ignore[assignment]
        try:
            assert (await cache.get_key(signer.kid))["kid"] == signer.kid
        finally:
            httpx.AsyncClient = real  # type: ignore[assignment]

    async def test_cold_cache_still_fails_closed(self):
        cache = JwksCache("http://unreachable.invalid:1/jwks.json", max_stale_seconds=0)
        with pytest.raises(InvalidToken):
            await cache.get_key("k")


# ─── session revocation fail_mode ─────────────────────────────────────────────

CheckDep = Depends(check_session_revocation)


@pytest.fixture
def redis() -> FakeRedis:
    return FakeRedis()


def _make_app(signer: Signer, redis: FakeRedis, *, mode: str, fail_mode: str) -> FastAPI:
    blumax_auth.reset()
    blumax_auth.reset_session_revocation()
    blumax_auth.configure(jwks_url="http://unused.invalid/jwks.json", issuer=ISSUER, audience=AUDIENCE)
    blumax_auth.jwks_cache().seed(signer.jwks())
    _configure(redis, mode=mode)
    import blumax_auth.session_revocation as sr

    sr._checker.fail_mode = fail_mode  # type: ignore[union-attr]
    app = FastAPI()
    blumax_auth.install_error_handler(app)

    @app.get("/checked")
    async def checked(ctx: blumax_auth.Auth, _: None = CheckDep) -> dict:
        return {"ok": True}

    return app


async def _get(app: FastAPI, token: str) -> httpx.Response:
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as c:
        return await c.get("/checked", headers={"Authorization": f"Bearer {token}"})


@pytest.fixture(autouse=True)
def _cleanup():
    yield
    blumax_auth.reset_session_revocation()
    blumax_auth.reset()


class TestFailMode:
    async def test_open_passes_on_redis_down_and_warns(self, signer, redis, caplog):
        app = _make_app(signer, redis, mode="enforce", fail_mode="open")
        redis.fail = ConnectionError("down")
        with caplog.at_level(logging.WARNING, logger=LOGGER):
            r = await _get(app, signer.token())
        assert r.status_code == 200
        assert any(x.getMessage() == "redis_unavailable" for x in caplog.records)

    async def test_closed_rejects_on_redis_down_with_401(self, signer, redis, caplog):
        app = _make_app(signer, redis, mode="enforce", fail_mode="closed")
        redis.fail = ConnectionError("down")
        with caplog.at_level(logging.WARNING, logger=LOGGER):
            r = await _get(app, signer.token())
        assert r.status_code == 401
        assert any(x.getMessage() == "redis_unavailable" for x in caplog.records)

    async def test_closed_rejects_malformed_marker(self, signer, redis):
        app = _make_app(signer, redis, mode="enforce", fail_mode="closed")
        uid = uuid.uuid4()
        redis.store[f"session_revoked_at:{uid}"] = "garbage"
        assert (await _get(app, signer.token(sub=str(uid)))).status_code == 401

    async def test_closed_healthy_redis_passes(self, signer, redis):
        app = _make_app(signer, redis, mode="enforce", fail_mode="closed")
        assert (await _get(app, signer.token())).status_code == 200

    async def test_closed_in_warn_mode_never_rejects(self, signer, redis):
        app = _make_app(signer, redis, mode="warn", fail_mode="closed")
        redis.fail = ConnectionError("down")
        assert (await _get(app, signer.token())).status_code == 200

    async def test_revoked_still_401_when_open(self, signer, redis):
        app = _make_app(signer, redis, mode="enforce", fail_mode="open")
        uid = uuid.uuid4()
        now = datetime.now(UTC)
        redis.revoke(uid, now)
        tok = signer.token(sub=str(uid), iat=now - timedelta(minutes=1))
        assert (await _get(app, tok)).status_code == 401


class TestConfigureFailMode:
    @pytest.fixture(autouse=True)
    def _url(self):
        pytest.importorskip("redis")

    def test_default_open(self, monkeypatch):
        monkeypatch.delenv("SESSION_REVOCATION_FAIL_MODE", raising=False)
        blumax_auth.configure_session_revocation("redis://127.0.0.1:1/0")
        import blumax_auth.session_revocation as sr

        assert sr._checker.fail_mode == "open"

    def test_env_closed(self, monkeypatch):
        monkeypatch.setenv("SESSION_REVOCATION_FAIL_MODE", "Closed")
        blumax_auth.configure_session_revocation("redis://127.0.0.1:1/0")
        import blumax_auth.session_revocation as sr

        assert sr._checker.fail_mode == "closed"

    def test_arg_overrides_env(self, monkeypatch):
        monkeypatch.setenv("SESSION_REVOCATION_FAIL_MODE", "closed")
        blumax_auth.configure_session_revocation("redis://127.0.0.1:1/0", fail_mode="open")
        import blumax_auth.session_revocation as sr

        assert sr._checker.fail_mode == "open"

    def test_invalid_arg_raises(self):
        with pytest.raises(ValueError):
            blumax_auth.configure_session_revocation("redis://127.0.0.1:1/0", fail_mode="maybe")  # type: ignore[arg-type]

    def test_invalid_env_raises(self, monkeypatch):
        monkeypatch.setenv("SESSION_REVOCATION_FAIL_MODE", "nope")
        with pytest.raises(ValueError):
            blumax_auth.configure_session_revocation("redis://127.0.0.1:1/0")
