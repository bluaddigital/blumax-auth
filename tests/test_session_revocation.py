"""blumax_auth.check_session_revocation — the opt-in session-revocation check.

Redis is replaced by an in-memory FakeRedis so the package is tested
standalone, matching test_permissions.py's own FakeCore approach. The
comparison logic under test must agree byte-for-byte with
blumax-backend's app/core/session_revocation.py::is_session_revoked — the two
sides of this contract are never allowed to drift.
"""
from __future__ import annotations

import logging
import uuid
from datetime import UTC, datetime, timedelta
from typing import Annotated

import httpx
import pytest
from fastapi import Depends, FastAPI
from test_verification import AUDIENCE, ISSUER, Signer

import blumax_auth
from blumax_auth.session_revocation import check_session_revocation

LOGGER = "blumax_auth.session_revocation"


# ─── Fakes ────────────────────────────────────────────────────────────────────

class FakeRedis:
    """Stands in for redis.asyncio.Redis: only .get/.set, matching what this
    module (and blumax-backend's writer side) actually uses.
    """

    def __init__(self) -> None:
        self.store: dict[str, str] = {}
        self.fail: Exception | None = None
        self.calls = 0

    async def get(self, key: str) -> str | None:
        self.calls += 1
        if self.fail is not None:
            raise self.fail
        return self.store.get(key)

    def revoke(self, user_id: uuid.UUID, at: datetime) -> None:
        """Write a marker exactly the way blumax-backend's revoke_user_sessions does."""
        self.store[f"session_revoked_at:{user_id}"] = at.isoformat()

    def exempt(self, user_id: uuid.UUID, jti: str) -> None:
        """Write an exemption exactly the way blumax-backend's
        exempt_jti_from_revocation does.
        """
        self.store[f"session_revoked_at:{user_id}:exempt:{jti}"] = "1"


def _configure(redis: FakeRedis, *, mode: str = "warn") -> None:
    # Bypasses configure_session_revocation()'s real redis.asyncio.from_url()
    # call so the fake client can be injected directly — the same seam
    # test_permissions.py uses via httpx.MockTransport for Core.
    import blumax_auth.session_revocation as sr

    sr._checker = sr._Checker(redis, mode=mode)  # type: ignore[arg-type]


# ─── Fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture
def signer() -> Signer:
    return Signer()


@pytest.fixture
def redis() -> FakeRedis:
    return FakeRedis()


CheckEnforce = Annotated[None, Depends(check_session_revocation)]


@pytest.fixture
def app(signer: Signer, redis: FakeRedis):
    blumax_auth.reset()
    blumax_auth.reset_session_revocation()
    blumax_auth.configure(jwks_url="http://unused.invalid/jwks.json", issuer=ISSUER, audience=AUDIENCE)
    blumax_auth.jwks_cache().seed(signer.jwks())
    _configure(redis, mode="warn")

    application = FastAPI()
    blumax_auth.install_error_handler(application)

    @application.get("/checked")
    async def checked(ctx: blumax_auth.Auth, _: CheckEnforce) -> dict:
        return {"user_id": str(ctx.user_id)}

    @application.get("/plain")
    async def plain(ctx: blumax_auth.Auth) -> dict:
        return {"user_id": str(ctx.user_id)}

    yield application
    blumax_auth.reset_session_revocation()
    blumax_auth.reset()


@pytest.fixture
async def client(app: FastAPI):
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as c:
        yield c


def _events(caplog) -> list[logging.LogRecord]:
    return [r for r in caplog.records if r.name == LOGGER and r.getMessage() == "session_revocation_check"]


# ─── Additive ─────────────────────────────────────────────────────────────────

class TestAdditive:
    def test_new_api_is_importable_from_the_package_root(self):
        from blumax_auth import (  # noqa: F401
            aclose_session_revocation,
            check_session_revocation,
            configure_session_revocation,
            reset_session_revocation,
        )

    def test_every_pre_existing_export_is_still_there(self):
        before = {
            "Auth", "AuthContext", "AuthError", "Forbidden", "InvalidToken", "JwksCache",
            "MissingCredentials", "PermissionCheckUnavailable", "TenantAuth",
            "TenantContextMissing", "TenantMismatch", "TokenVerifier",
            "aclose_permissions", "configure", "configure_permissions",
            "install_error_handler", "jwks_cache", "require_auth", "require_archetype",
            "require_permission", "require_role", "require_tenant", "reset", "reset_permissions",
        }
        assert before <= set(blumax_auth.__all__)
        assert all(hasattr(blumax_auth, name) for name in before)

    async def test_a_route_without_the_dependency_is_unaffected_even_when_revoked(
        self, signer, redis,
    ):
        # A service that never adds check_session_revocation to a route sees
        # no behavior change at all, even if a marker exists.
        blumax_auth.reset()
        blumax_auth.reset_session_revocation()
        blumax_auth.configure(jwks_url="http://unused.invalid/j", issuer=ISSUER, audience=AUDIENCE)
        blumax_auth.jwks_cache().seed(signer.jwks())
        _configure(redis, mode="enforce")

        application = FastAPI()
        blumax_auth.install_error_handler(application)

        @application.get("/scoped")
        async def scoped(ctx: blumax_auth.Auth) -> dict:
            return {"user_id": str(ctx.user_id)}

        uid = uuid.uuid4()
        token = signer.token(sub=str(uid))
        redis.revoke(uid, datetime.now(UTC) + timedelta(seconds=10))

        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=application), base_url="http://t") as c:
            r = await c.get("/scoped", headers={"Authorization": f"Bearer {token}"})
            assert r.status_code == 200
        blumax_auth.reset()


# ─── Allow: no revocation ──────────────────────────────────────────────────────

class TestAllow:
    async def test_no_marker_at_all_is_allowed(self, client, signer, redis):
        token = signer.token()
        r = await client.get("/checked", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200

    async def test_a_marker_older_than_the_token_is_allowed(self, client, signer, redis):
        uid = uuid.uuid4()
        now = datetime.now(UTC)
        token = signer.token(sub=str(uid), iat=now)
        redis.revoke(uid, now - timedelta(minutes=5))     # revoked BEFORE this token was minted
        r = await client.get("/checked", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200


# ─── Enforce: reject a genuinely revoked session ───────────────────────────────

class TestEnforceReject:
    async def test_a_token_issued_before_the_marker_is_rejected(self, signer, redis):
        _configure(redis, mode="enforce")
        blumax_auth.reset()
        blumax_auth.configure(jwks_url="http://unused.invalid/j", issuer=ISSUER, audience=AUDIENCE)
        blumax_auth.jwks_cache().seed(signer.jwks())

        application = FastAPI()
        blumax_auth.install_error_handler(application)

        @application.get("/checked")
        async def checked(ctx: blumax_auth.Auth, _: CheckEnforce) -> dict:
            return {"user_id": str(ctx.user_id)}

        uid = uuid.uuid4()
        now = datetime.now(UTC)
        token = signer.token(sub=str(uid), iat=now - timedelta(minutes=5))
        redis.revoke(uid, now)

        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=application), base_url="http://t") as c:
            r = await c.get("/checked", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 401
        assert r.json()["error"]["code"] == "AUTHENTICATION_FAILED"
        blumax_auth.reset()
        blumax_auth.reset_session_revocation()


# ─── jti exemption ──────────────────────────────────────────────────────────────

class TestJtiExemption:
    async def _run(
        self, signer, redis, *, jti: str, exempt_jti: str | None, mode: str = "enforce"
    ):
        _configure(redis, mode=mode)
        blumax_auth.reset()
        blumax_auth.configure(jwks_url="http://unused.invalid/j", issuer=ISSUER, audience=AUDIENCE)
        blumax_auth.jwks_cache().seed(signer.jwks())

        application = FastAPI()
        blumax_auth.install_error_handler(application)

        @application.get("/checked")
        async def checked(ctx: blumax_auth.Auth, _: CheckEnforce) -> dict:
            return {"user_id": str(ctx.user_id)}

        uid = uuid.uuid4()
        now = datetime.now(UTC)
        # issued_at is BEFORE the revocation marker in every case here — the
        # only thing that should ever save it is an explicit exemption.
        token = signer.token(sub=str(uid), iat=now - timedelta(minutes=5), jti=jti)
        redis.revoke(uid, now)
        if exempt_jti is not None:
            redis.exempt(uid, exempt_jti)

        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=application), base_url="http://t") as c:
            r = await c.get("/checked", headers={"Authorization": f"Bearer {token}"})
        blumax_auth.reset()
        blumax_auth.reset_session_revocation()
        return r

    async def test_a_jti_explicitly_exempted_is_never_revoked_even_though_issued_before_the_marker(
        self, signer, redis,
    ):
        # Mirrors force_login's own brand-new token: iat predates the marker
        # it just wrote (minted moments earlier in the same call), but its
        # jti was explicitly spared.
        jti = str(uuid.uuid4())
        r = await self._run(signer, redis, jti=jti, exempt_jti=jti)
        assert r.status_code == 200

    async def test_a_jti_not_exempted_with_issued_at_before_the_marker_is_revoked_strictly(
        self, signer, redis,
    ):
        # No grace window: an ordinary older session, issued close in time to
        # the revocation but NOT the exempted one, is revoked outright.
        r = await self._run(
            signer, redis, jti=str(uuid.uuid4()), exempt_jti=str(uuid.uuid4())
        )
        assert r.status_code == 401

    async def test_an_exemption_for_a_different_user_does_not_protect_this_token(
        self, signer, redis,
    ):
        jti = str(uuid.uuid4())
        _configure(redis, mode="enforce")
        blumax_auth.reset()
        blumax_auth.configure(jwks_url="http://unused.invalid/j", issuer=ISSUER, audience=AUDIENCE)
        blumax_auth.jwks_cache().seed(signer.jwks())

        application = FastAPI()
        blumax_auth.install_error_handler(application)

        @application.get("/checked")
        async def checked(ctx: blumax_auth.Auth, _: CheckEnforce) -> dict:
            return {"user_id": str(ctx.user_id)}

        uid = uuid.uuid4()
        other_uid = uuid.uuid4()
        now = datetime.now(UTC)
        token = signer.token(sub=str(uid), iat=now - timedelta(minutes=5), jti=jti)
        redis.revoke(uid, now)
        redis.exempt(other_uid, jti)  # same jti, wrong user's exemption key

        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=application), base_url="http://t") as c:
            r = await c.get("/checked", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 401
        blumax_auth.reset()
        blumax_auth.reset_session_revocation()

    async def test_issued_at_after_the_marker_is_allowed_without_needing_an_exemption(
        self, client, signer, redis,
    ):
        uid = uuid.uuid4()
        now = datetime.now(UTC)
        token = signer.token(sub=str(uid), iat=now + timedelta(seconds=5))
        redis.revoke(uid, now)
        r = await client.get("/checked", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200


# ─── Warn mode ──────────────────────────────────────────────────────────────────

class TestWarnMode:
    async def test_a_would_be_rejection_is_logged_and_not_rejected(self, client, signer, redis, caplog):
        uid = uuid.uuid4()
        now = datetime.now(UTC)
        token = signer.token(sub=str(uid), iat=now - timedelta(minutes=5))
        redis.revoke(uid, now)
        with caplog.at_level(logging.INFO, logger=LOGGER):
            r = await client.get("/checked", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200
        (rec,) = _events(caplog)
        assert rec.levelno == logging.WARNING
        assert rec.decision == "would_reject"
        assert rec.mode == "warn"
        assert rec.user_id == str(uid)
        assert hasattr(rec, "revoked_at")

    async def test_an_allowed_caller_is_logged_at_info(self, client, signer, redis, caplog):
        token = signer.token()
        with caplog.at_level(logging.INFO, logger=LOGGER):
            r = await client.get("/checked", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200
        (rec,) = _events(caplog)
        assert rec.levelno == logging.INFO
        assert rec.decision == "allow"
        assert not hasattr(rec, "reason")

    async def test_no_configuration_logs_check_failed_not_configured_and_passes(
        self, client, signer, caplog,
    ):
        blumax_auth.reset_session_revocation()
        token = signer.token()
        with caplog.at_level(logging.INFO, logger=LOGGER):
            r = await client.get("/checked", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200
        (rec,) = _events(caplog)
        assert rec.decision == "check_failed" and rec.reason == "not_configured"

    async def test_the_log_never_carries_a_token(self, client, signer, redis, caplog):
        token = signer.token()
        with caplog.at_level(logging.DEBUG, logger=LOGGER):
            await client.get("/checked", headers={"Authorization": f"Bearer {token}"})
        for rec in caplog.records:
            dumped = repr(vars(rec)) + rec.getMessage()
            assert token not in dumped


# ─── Fail-open: Redis unreachable ──────────────────────────────────────────────

class TestFailOpen:
    async def test_redis_unreachable_is_allowed_in_enforce_mode(self, signer, redis):
        _configure(redis, mode="enforce")
        blumax_auth.reset()
        blumax_auth.configure(jwks_url="http://unused.invalid/j", issuer=ISSUER, audience=AUDIENCE)
        blumax_auth.jwks_cache().seed(signer.jwks())

        application = FastAPI()
        blumax_auth.install_error_handler(application)

        @application.get("/checked")
        async def checked(ctx: blumax_auth.Auth, _: CheckEnforce) -> dict:
            return {"user_id": str(ctx.user_id)}

        uid = uuid.uuid4()
        now = datetime.now(UTC)
        token = signer.token(sub=str(uid), iat=now - timedelta(minutes=5))
        redis.revoke(uid, now)          # would be revoked...
        redis.fail = ConnectionError("redis down")   # ...but Redis is unreachable

        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=application), base_url="http://t") as c:
            r = await c.get("/checked", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200, r.text
        blumax_auth.reset()
        blumax_auth.reset_session_revocation()

    async def test_redis_unreachable_is_logged_check_failed_in_warn_mode(
        self, client, signer, redis, caplog,
    ):
        redis.fail = TimeoutError("slow")
        token = signer.token()
        with caplog.at_level(logging.INFO, logger=LOGGER):
            r = await client.get("/checked", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200
        (rec,) = _events(caplog)
        assert rec.decision == "check_failed" and rec.reason == "redis_unavailable"

    async def test_a_malformed_marker_is_allowed_and_logged_check_failed(
        self, client, signer, redis, caplog,
    ):
        uid = uuid.uuid4()
        token = signer.token(sub=str(uid))
        redis.store[f"session_revoked_at:{uid}"] = "not-a-timestamp"
        with caplog.at_level(logging.INFO, logger=LOGGER):
            r = await client.get("/checked", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200
        (rec,) = _events(caplog)
        assert rec.decision == "check_failed" and rec.reason == "marker_malformed"


# ─── Configuration and misuse ──────────────────────────────────────────────────

class TestConfiguration:
    def test_bad_configuration_is_refused_at_startup(self):
        for bad_url, bad_mode in [("", "warn"), ("  ", "warn")]:
            with pytest.raises(ValueError):
                blumax_auth.configure_session_revocation(bad_url, mode=bad_mode)
        with pytest.raises(ValueError):
            blumax_auth.configure_session_revocation("redis://localhost", mode="audit")  # type: ignore[arg-type]

    async def test_close_is_safe_to_call_whether_or_not_it_was_used(self):
        await blumax_auth.aclose_session_revocation()   # unconfigured: no error


# ─── Wire-format agreement with blumax-backend ─────────────────────────────────

class TestWireFormatAgreement:
    def test_the_redis_key_matches_blumax_backends_writer(self):
        from blumax_auth.session_revocation import _key

        uid = uuid.uuid4()
        assert _key(uid) == f"session_revoked_at:{uid}"

    def test_the_exempt_key_matches_blumax_backends_writer(self):
        from blumax_auth.session_revocation import _exempt_key

        uid = uuid.uuid4()
        jti = str(uuid.uuid4())
        assert _exempt_key(uid, jti) == f"session_revoked_at:{uid}:exempt:{jti}"
