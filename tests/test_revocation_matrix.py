"""SEC-09 / SEC-10: the executable token-expiry and session-revocation matrix for every service that verifies Core JWTs.

One contract, run once per consumer PROFILE. A profile is how a deployed service really wires blumax-auth (read from
that service's `origin/dev`, recorded in PROFILES below and re-checked against the sibling repositories by
`TestConsumerWiring`). The scenarios are the rows of the matrix; the profiles are its columns:

    row                                         what must hold
    ------------------------------------------  --------------------------------------------------------------------
    expired token                               401 (every consumer; signature layer, no Redis involved)
    token signed with the wrong key             401 (every consumer)
    wrong issuer / audience / tampered / alg    401 (every consumer)
    logout (all-devices) marker                 401 where the service checks revocation
    forced logout (force_login / admin revoke)  401 for the older session, the new session and its jti stay valid
    Redis down (error)                          fail_mode open -> 200 + `redis_unavailable` warning; closed -> 401
    Redis hung                                  one bounded timeout, then the breaker answers at once (no 5xx storm)
    Redis flushed or key evicted                200 in BOTH fail modes: RESIDUAL WINDOW (see below). Strict xfail pins the target.
    Redis back                                  after the breaker window the marker is read again: revoked -> 401, others -> 200
    real Redis (opt-in container tests)         the same, against a real server: outage, restart with and without AOF,
                                                allkeys-lru eviction, noeviction

The residual window (SEC-01), stated once and tested below: this library has NO authoritative store. It only reads the
`session_revoked_at:{user_id}` marker Core wrote into the shared Redis. If that marker is gone because of a flush, a restart
without persistence, or an `allkeys-lru` eviction, the library cannot tell "never revoked" from "revoked, then lost": the
token is accepted in `open` AND in `closed` mode (`closed` only covers Redis ERRORS). The window lasts until the token's own
expiry (human tokens: the next 02:00 IST, up to ~24 h). Closing it needs the Postgres-backed authority (SEC-01 phase A/B) and
Core's session-state answer, or at minimum a never-evicting Redis for these keys (`redis-sec` / noeviction, MSG-01). The
`xfail(strict=True)` tests below state the desired behaviour; when SEC-01 lands in the library they start passing, strict mode
turns that into a failure, and whoever lands it must flip them into plain tests.

Services that verify tokens but do NOT check revocation at all (DIS, CDSS, WA service, Composer) are the `no-check`
profiles: their revoked-session row documents the present behaviour (accepted) so the gap is visible and cannot change
silently. Closing it is `configure_session_revocation` + `check_session_revocation` in that service.

Tokens here are signed with a key generated per test run. Nothing in this module is a secret.
"""
from __future__ import annotations

import asyncio
import base64
import json
import logging
import os
import shutil
import socket
import subprocess
import time
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Annotated

import httpx
import pytest
from fastapi import Depends, FastAPI
from test_verification import AUDIENCE, ISSUER, Signer

import blumax_auth
import blumax_auth.session_revocation as sr
from blumax_auth.session_revocation import check_session_revocation

LOGGER = "blumax_auth.session_revocation"


# ─── The matrix columns ───────────────────────────────────────────────────────

@dataclass(frozen=True)
class Profile:
    name: str
    #: does the service call configure_session_revocation + check_session_revocation at all
    checks_revocation: bool
    #: the library fail_mode the service ends up with ("open" is the library default)
    fail_mode: str
    #: where it is wired (file in the service repository, `origin/dev`)
    wired_in: str
    #: substrings that must be present (or, for no-check services, absent) in the service's source at that ref
    markers: tuple[str, ...]
    note: str = ""


PROFILES: tuple[Profile, ...] = (
    Profile("opd", True, "open", "app/main.py", ("configure_session_revocation",)),
    Profile("ipd", True, "open", "app/main.py", ("configure_session_revocation",)),
    Profile("appointments", True, "open", "app/main.py", ("configure_session_revocation", "check_session_revocation")),
    Profile("billing", True, "open", "api/app/main.py", ("configure_session_revocation",)),
    Profile("accounts", True, "open", "backend/api/app/main.py", ("configure_session_revocation",)),
    Profile("notifications", True, "open", "app/main.py", ("configure_session_revocation", "check_session_revocation")),
    Profile("reporting", True, "open", "app/main.py", ("configure_session_revocation", "check_session_revocation")),
    Profile("pharm", True, "open", "pharmacy_backend/app/main.py", ("configure_session_revocation",),
            "Core-token paths only; Pharmacy-native HS256 tokens are not covered"),
    Profile("pacs-imaging", True, "open", "imaging/app/main.py", ("configure_session_revocation",)),
    Profile("superadmin", True, "open", "superadmin-backend/app/main.py", ("configure_session_revocation",),
            "only when AUTH_PROVIDER=blumax_auth and BLUMAX_AUTH_REVOCATION_REDIS_URL is set"),
    Profile("labs", True, "closed", "labs-backend/app/main.py", ("fail_mode=settings.SESSION_REVOCATION_FAIL_MODE",),
            "closed by default (SESSION_REVOCATION_FAIL_MODE); also refuses a Core token when unconfigured"),
    # Verify tokens through blumax-auth, never check revocation (verified at origin/dev, SEC-09 gap):
    Profile("dis", False, "open", "app/main.py", ("configure_session_revocation",)),
    Profile("cdss-platform", False, "open", "app/main.py", ("configure_session_revocation",)),
    Profile("wa-service", False, "open", "whatsapp-notification-service/app/main.py", ("configure_session_revocation",)),
    Profile("composer", False, "open", "app/main.py", ("configure_session_revocation",),
            "blumax-clinical-ai, pinned blumax-auth 0.5.0"),
)
CHECKING = tuple(p for p in PROFILES if p.checks_revocation)
CLOSED = tuple(p for p in CHECKING if p.fail_mode == "closed")
OPEN = tuple(p for p in CHECKING if p.fail_mode == "open")


def _ids(profiles):
    return [p.name for p in profiles]


# ─── Fakes ────────────────────────────────────────────────────────────────────

class FakeRedis:
    """The Redis surface the library uses (mget/get), with switches for the failure modes."""

    def __init__(self) -> None:
        self.store: dict[str, str] = {}
        self.fail: Exception | None = None
        self.hang = False
        self.calls = 0

    async def _gate(self) -> None:
        self.calls += 1
        if self.hang:
            await asyncio.Event().wait()
        if self.fail is not None:
            raise self.fail

    async def mget(self, keys):
        await self._gate()
        return [self.store.get(k) for k in keys]

    async def get(self, key):
        await self._gate()
        return self.store.get(key)

    # Writer side, byte-identical to blumax-backend app/core/session_revocation.py
    def revoke(self, user_id, at: datetime) -> None:
        self.store[f"session_revoked_at:{user_id}"] = at.isoformat()

    def exempt(self, user_id, jti: str) -> None:
        self.store[f"session_revoked_at:{user_id}:exempt:{jti}"] = "1"


def _breaker_window_passes(monkeypatch, seconds: float = 11.0) -> None:
    real = sr._clock
    monkeypatch.setattr(sr, "_clock", lambda: real() + seconds)


# ─── Harness ──────────────────────────────────────────────────────────────────

class Harness:
    """A consumer service as the matrix sees it: blumax-auth verification, plus the revocation check when the profile has one."""

    def __init__(self, profile: Profile, signer: Signer, redis, monkeypatch) -> None:
        self.profile, self.signer, self.redis = profile, signer, redis
        blumax_auth.reset()
        blumax_auth.reset_session_revocation()
        blumax_auth.configure(jwks_url="http://unused.invalid/jwks.json", issuer=ISSUER, audience=AUDIENCE)
        blumax_auth.jwks_cache().seed(signer.jwks())
        if profile.checks_revocation:
            sr._checker = sr._Checker(redis, mode="enforce", fail_mode=profile.fail_mode)  # type: ignore[arg-type]
        app = FastAPI()
        blumax_auth.install_error_handler(app)
        if profile.checks_revocation:
            @app.get("/protected")
            async def protected(ctx: blumax_auth.Auth, _: Annotated[None, Depends(check_session_revocation)]) -> dict:
                return {"user_id": str(ctx.user_id)}
        else:
            @app.get("/protected")
            async def protected_unchecked(ctx: blumax_auth.Auth) -> dict:
                return {"user_id": str(ctx.user_id)}
        self.app = app

    async def call(self, token: str | None) -> httpx.Response:
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=self.app), base_url="http://t") as c:
            return await c.get("/protected", headers=headers)

    def token(self, user_id=None, **over) -> tuple[str, uuid.UUID, str]:
        uid = user_id or uuid.uuid4()
        jti = str(uuid.uuid4())
        over.setdefault("iat", datetime.now(UTC) - timedelta(minutes=5))
        return self.signer.token(sub=str(uid), jti=jti, **over), uid, jti


@pytest.fixture(autouse=True)
def _reset_between_tests():
    yield
    blumax_auth.reset_session_revocation()
    blumax_auth.reset()


@pytest.fixture
def redis() -> FakeRedis:
    return FakeRedis()


@pytest.fixture(params=PROFILES, ids=_ids(PROFILES))
def any_consumer(request, redis, monkeypatch) -> Harness:
    return Harness(request.param, Signer(), redis, monkeypatch)


@pytest.fixture(params=CHECKING, ids=_ids(CHECKING))
def checking_consumer(request, redis, monkeypatch) -> Harness:
    return Harness(request.param, Signer(), redis, monkeypatch)


@pytest.fixture(params=OPEN, ids=_ids(OPEN))
def open_consumer(request, redis, monkeypatch) -> Harness:
    return Harness(request.param, Signer(), redis, monkeypatch)


@pytest.fixture(params=CLOSED, ids=_ids(CLOSED))
def closed_consumer(request, redis, monkeypatch) -> Harness:
    return Harness(request.param, Signer(), redis, monkeypatch)


@pytest.fixture(params=[p for p in PROFILES if not p.checks_revocation], ids=lambda p: p.name)
def unchecked_consumer(request, redis, monkeypatch) -> Harness:
    return Harness(request.param, Signer(), redis, monkeypatch)


@pytest.fixture(autouse=True)
def _short_redis_timeouts(monkeypatch):
    monkeypatch.setenv("SESSION_REVOCATION_REDIS_TIMEOUT_SECONDS", "0.2")
    monkeypatch.setenv("SESSION_REVOCATION_BREAKER_SECONDS", "10")


def _redis_warnings(caplog) -> list[logging.LogRecord]:
    return [r for r in caplog.records if r.name == LOGGER and r.getMessage() == "redis_unavailable"]


# ─── Row 1-3: token verification (every consumer, no Redis involved) ──────────

class TestTokenVerification:
    async def test_a_valid_token_is_accepted(self, any_consumer):
        token, uid, _ = any_consumer.token()
        r = await any_consumer.call(token)
        assert r.status_code == 200, r.text
        assert r.json()["user_id"] == str(uid)

    async def test_no_token_is_401(self, any_consumer):
        assert (await any_consumer.call(None)).status_code == 401

    async def test_an_expired_token_is_401(self, any_consumer):
        now = datetime.now(UTC)
        token, _, _ = any_consumer.token(iat=now - timedelta(hours=2), exp=now - timedelta(hours=1))
        assert (await any_consumer.call(token)).status_code == 401

    async def test_a_token_signed_with_the_wrong_key_is_401(self, any_consumer):
        rogue = Signer(kid=any_consumer.signer.kid)  # same kid, different private key
        token = rogue.token(sub=str(uuid.uuid4()))
        assert (await any_consumer.call(token)).status_code == 401

    @pytest.mark.parametrize("claim,value", [("iss", "https://evil.example"), ("aud", "someone-else")])
    async def test_wrong_issuer_or_audience_is_401(self, any_consumer, claim, value):
        token, _, _ = any_consumer.token(**{claim: value})
        assert (await any_consumer.call(token)).status_code == 401

    async def test_a_tampered_payload_is_401(self, any_consumer):
        token, _, _ = any_consumer.token()
        head, payload, sig = token.split(".")
        body = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
        body["adm"] = True
        forged = base64.urlsafe_b64encode(json.dumps(body).encode()).rstrip(b"=").decode()
        assert (await any_consumer.call(f"{head}.{forged}.{sig}")).status_code == 401

    async def test_an_unsigned_alg_none_token_is_401(self, any_consumer):
        def b64(d):
            return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()
        now = int(time.time())
        token = f"{b64({'alg': 'none', 'typ': 'JWT'})}.{b64({'iss': ISSUER, 'aud': AUDIENCE, 'sub': str(uuid.uuid4()), 'exp': now + 600, 'iat': now})}."
        assert (await any_consumer.call(token)).status_code == 401

    async def test_an_expired_token_is_refused_before_redis_is_asked(self, checking_consumer):
        now = datetime.now(UTC)
        token, _, _ = checking_consumer.token(iat=now - timedelta(hours=2), exp=now - timedelta(hours=1))
        assert (await checking_consumer.call(token)).status_code == 401
        assert checking_consumer.redis.calls == 0


# ─── Row 4-5: logout and forced logout (the marker Core writes) ───────────────

class TestRevokedSession:
    async def test_logout_all_devices_rejects_the_older_token(self, checking_consumer):
        token, uid, _ = checking_consumer.token()
        assert (await checking_consumer.call(token)).status_code == 200
        checking_consumer.redis.revoke(uid, datetime.now(UTC))          # Core: logout(all_devices=True)
        assert (await checking_consumer.call(token)).status_code == 401

    async def test_forced_logout_rejects_the_old_session_and_keeps_the_new_one(self, checking_consumer):
        uid = uuid.uuid4()
        old, _, _ = checking_consumer.token(uid)
        checking_consumer.redis.revoke(uid, datetime.now(UTC))          # Core: force_login / admin revoke
        new_iat = datetime.now(UTC) + timedelta(seconds=2)              # minted after the marker (mint_wait_past_cutoff)
        new, _, _ = checking_consumer.token(uid, iat=new_iat, exp=new_iat + timedelta(minutes=10))
        assert (await checking_consumer.call(old)).status_code == 401
        assert (await checking_consumer.call(new)).status_code == 200

    async def test_the_exempted_jti_of_a_force_login_survives_its_own_marker(self, checking_consumer):
        uid = uuid.uuid4()
        token, _, jti = checking_consumer.token(uid)
        checking_consumer.redis.revoke(uid, datetime.now(UTC) + timedelta(seconds=1))
        assert (await checking_consumer.call(token)).status_code == 401
        checking_consumer.redis.exempt(uid, jti)
        assert (await checking_consumer.call(token)).status_code == 200

    async def test_one_users_revocation_does_not_touch_another_user(self, checking_consumer):
        victim, bystander = uuid.uuid4(), uuid.uuid4()
        t_victim, _, _ = checking_consumer.token(victim)
        t_other, _, _ = checking_consumer.token(bystander)
        checking_consumer.redis.revoke(victim, datetime.now(UTC))
        assert (await checking_consumer.call(t_victim)).status_code == 401
        assert (await checking_consumer.call(t_other)).status_code == 200

    async def test_a_token_minted_after_the_marker_is_accepted(self, checking_consumer):
        uid = uuid.uuid4()
        checking_consumer.redis.revoke(uid, datetime.now(UTC) - timedelta(minutes=5))
        token, _, _ = checking_consumer.token(uid, iat=datetime.now(UTC) - timedelta(minutes=1))
        assert (await checking_consumer.call(token)).status_code == 200

    async def test_KNOWN_GAP_services_without_a_revocation_check_accept_a_revoked_session(self, unchecked_consumer):
        """SEC-09 gap, pinned. Wiring configure_session_revocation + check_session_revocation into the service closes it; then
        move that service's Profile to checks_revocation=True and this row stops applying to it."""
        token, uid, _ = unchecked_consumer.token()
        unchecked_consumer.redis.revoke(uid, datetime.now(UTC))
        assert (await unchecked_consumer.call(token)).status_code == 200


# ─── Row 6: Redis down, hung ──────────────────────────────────────────────────

class TestRedisDown:
    """Documented expectation: `open` serves the request and logs `redis_unavailable` (alertable); `closed` answers the same 401
    a revoked session gets. Neither ever answers 5xx: no error storm from a Redis outage."""

    async def test_open_mode_serves_requests_and_logs_the_degradation(self, open_consumer, caplog):
        token, uid, _ = open_consumer.token()
        open_consumer.redis.revoke(uid, datetime.now(UTC))
        open_consumer.redis.fail = ConnectionError("redis down")
        with caplog.at_level(logging.WARNING, logger=LOGGER):
            r = await open_consumer.call(token)
        assert r.status_code == 200          # the residual window while Redis is down: a revoked session still passes
        assert _redis_warnings(caplog), "an outage in open mode must be loud (alert on `redis_unavailable`)"

    async def test_closed_mode_refuses_while_redis_is_down(self, closed_consumer, caplog):
        token, _, _ = closed_consumer.token()
        closed_consumer.redis.fail = ConnectionError("redis down")
        with caplog.at_level(logging.WARNING, logger=LOGGER):
            r = await closed_consumer.call(token)
        assert r.status_code == 401
        assert _redis_warnings(caplog)

    async def test_an_outage_never_produces_a_5xx(self, checking_consumer):
        for failure in (ConnectionError("down"), TimeoutError("slow"), OSError("reset"), RuntimeError("anything")):
            checking_consumer.redis.fail = failure
            sr._checker._skip_until = 0.0  # type: ignore[union-attr]  # ask Redis again each time
            token, _, _ = checking_consumer.token()
            assert (await checking_consumer.call(token)).status_code in (200, 401)

    async def test_a_hung_redis_costs_one_timeout_then_the_breaker_answers_at_once(self, checking_consumer):
        checking_consumer.redis.hang = True
        tokens = [checking_consumer.token()[0] for _ in range(20)]
        started = time.monotonic()
        first = await checking_consumer.call(tokens[0])
        first_took = time.monotonic() - started
        assert first_took < 1.0, f"bounded by the 0.2 s timeout, took {first_took:.2f}s"
        started = time.monotonic()
        rest = [await checking_consumer.call(t) for t in tokens[1:]]
        assert time.monotonic() - started < 1.0, "19 further requests during the breaker window must not each wait"
        expected = 401 if checking_consumer.profile.fail_mode == "closed" else 200
        assert {first.status_code, *(r.status_code for r in rest)} == {expected}
        assert checking_consumer.redis.calls == 1, "Redis was asked once; the breaker skipped it for the others"

    async def test_unchecked_services_are_untouched_by_a_redis_outage(self, unchecked_consumer):
        unchecked_consumer.redis.hang = True
        token, _, _ = unchecked_consumer.token()
        assert (await unchecked_consumer.call(token)).status_code == 200
        assert unchecked_consumer.redis.calls == 0


# ─── Row 7: Redis back ────────────────────────────────────────────────────────

class TestRecovery:
    async def test_after_the_breaker_window_the_marker_is_read_again(self, checking_consumer, monkeypatch):
        revoked_token, uid, _ = checking_consumer.token()
        healthy_token, _, _ = checking_consumer.token()
        checking_consumer.redis.revoke(uid, datetime.now(UTC))
        checking_consumer.redis.fail = ConnectionError("down")
        await checking_consumer.call(healthy_token)                      # opens the breaker
        checking_consumer.redis.fail = None                              # Redis returns
        _breaker_window_passes(monkeypatch)
        assert (await checking_consumer.call(revoked_token)).status_code == 401, "revoked again once Redis answers"
        assert (await checking_consumer.call(healthy_token)).status_code == 200, "no lasting lock-out after the outage"

    async def test_during_the_breaker_window_recovery_is_not_yet_visible(self, open_consumer):
        """The documented price of the breaker: up to SESSION_REVOCATION_BREAKER_SECONDS (10 s default) after Redis returns,
        open-mode services still skip it. Bounded, and the same window the outage itself already had."""
        token, uid, _ = open_consumer.token()
        open_consumer.redis.revoke(uid, datetime.now(UTC))
        open_consumer.redis.fail = ConnectionError("down")
        await open_consumer.call(token)
        open_consumer.redis.fail = None
        assert (await open_consumer.call(token)).status_code == 200


# ─── Row 8: Redis flushed / evicted: the SEC-01 residual window ───────────────

class TestFlushedOrEvicted:
    async def test_RESIDUAL_WINDOW_a_flush_makes_a_revoked_session_valid_again_in_every_fail_mode(self, checking_consumer):
        token, uid, _ = checking_consumer.token()
        checking_consumer.redis.revoke(uid, datetime.now(UTC))
        assert (await checking_consumer.call(token)).status_code == 401
        checking_consumer.redis.store.clear()                            # FLUSHALL / restart without AOF / allkeys-lru eviction
        r = await checking_consumer.call(token)
        assert r.status_code == 200, "if this fails, the library gained an authority: flip the xfail below into a plain test"

    async def test_RESIDUAL_WINDOW_a_lost_exemption_is_the_inverse_failure(self, checking_consumer):
        """An evicted exemption (60 s TTL) makes a legitimately minted token look revoked: availability, not security."""
        uid = uuid.uuid4()
        token, _, jti = checking_consumer.token(uid)
        checking_consumer.redis.revoke(uid, datetime.now(UTC) + timedelta(seconds=1))
        checking_consumer.redis.exempt(uid, jti)
        assert (await checking_consumer.call(token)).status_code == 200
        checking_consumer.redis.store.pop(f"session_revoked_at:{uid}:exempt:{jti}")
        assert (await checking_consumer.call(token)).status_code == 401

    @pytest.mark.xfail(strict=True, reason="SEC-01: revocation is only a marker in evictable Redis; the Postgres authority (Core "
                       "session-state answer) does not exist yet. Target: a flush must not re-validate a revoked session.")
    async def test_TARGET_a_flush_must_not_make_a_revoked_session_valid(self, closed_consumer):
        token, uid, _ = closed_consumer.token()
        closed_consumer.redis.revoke(uid, datetime.now(UTC))
        closed_consumer.redis.store.clear()
        assert (await closed_consumer.call(token)).status_code == 401


# ─── Consumer wiring (reads the sibling repositories; opt in) ─────────────────

class TestConsumerWiring:
    """Re-checks PROFILES against the services' real source, so the matrix cannot drift from the code.

    BLUMAX_CONSUMERS_ROOT=/home/BluMax_Health  BLUMAX_CONSUMERS_REF=origin/dev  pytest tests/test_revocation_matrix.py -k Wiring
    Uses `git show <ref>:<file>`: no working tree is read or touched. Skipped when the root is not set.
    """

    ROOT = os.environ.get("BLUMAX_CONSUMERS_ROOT")
    REF = os.environ.get("BLUMAX_CONSUMERS_REF", "origin/dev")
    REPO = {"pacs-imaging": "blumax-pacs", "composer": "blumax-clinical-ai", "dis": "blumax-dis", "wa-service": "blumax-wa-service",
            "cdss-platform": "blumax-cdss-platform"}

    @pytest.mark.skipif(not ROOT, reason="set BLUMAX_CONSUMERS_ROOT to the directory holding the blumax-* checkouts")
    @pytest.mark.parametrize("profile", PROFILES, ids=_ids(PROFILES))
    def test_the_profile_matches_the_service_source(self, profile):
        repo = Path(self.ROOT) / self.REPO.get(profile.name, f"blumax-{profile.name}")
        shown = subprocess.run(["git", "-C", str(repo), "show", f"{self.REF}:{profile.wired_in}"], capture_output=True, text=True)
        if shown.returncode != 0:
            pytest.skip(f"{repo.name}@{self.REF} has no {profile.wired_in}: {shown.stderr.strip()[:120]}")
        for marker in profile.markers:
            present = marker in shown.stdout
            assert present == profile.checks_revocation, (
                f"{profile.name}: `{marker}` {'is' if present else 'is not'} in {profile.wired_in}@{self.REF}, the matrix says "
                f"checks_revocation={profile.checks_revocation}. Update PROFILES (and the matrix doc) in the same change."
            )


# ─── Real Redis (opt in): the same rows against a server, with a unique disposable container ───────────────────

_REAL = os.environ.get("BLUMAX_AUTH_TEST_REDIS_CONTAINER") == "1" and shutil.which("docker") is not None
needs_container = pytest.mark.skipif(not _REAL, reason="set BLUMAX_AUTH_TEST_REDIS_CONTAINER=1 (needs docker, image redis:7-alpine)")


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class RedisContainer:
    def __init__(self, *args: str) -> None:
        self.name = f"claude-authmx-redis-{uuid.uuid4().hex[:10]}"
        self.port = _free_port()
        subprocess.run(["docker", "run", "-d", "--name", self.name, "-p", f"127.0.0.1:{self.port}:6379", "redis:7-alpine",
                        "redis-server", *args], check=True, capture_output=True)
        self.url = f"redis://127.0.0.1:{self.port}/0"
        self.wait_ready()

    def wait_ready(self) -> None:
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            if subprocess.run(["docker", "exec", self.name, "redis-cli", "ping"], capture_output=True, text=True).stdout.strip() == "PONG":
                return
            time.sleep(0.2)
        raise RuntimeError("redis container did not become ready")

    def cli(self, *args: str) -> str:
        return subprocess.run(["docker", "exec", self.name, "redis-cli", *args], capture_output=True, text=True).stdout.strip()

    def stop(self) -> None:
        subprocess.run(["docker", "stop", "-t", "1", self.name], check=True, capture_output=True)

    def start(self) -> None:
        subprocess.run(["docker", "start", self.name], check=True, capture_output=True)
        self.wait_ready()

    def remove(self) -> None:
        subprocess.run(["docker", "rm", "-f", self.name], capture_output=True)


@pytest.fixture
def container_factory():
    made: list[RedisContainer] = []

    def make(*args: str) -> RedisContainer:
        c = RedisContainer(*args)
        made.append(c)
        return c

    yield make
    for c in made:
        c.remove()


class RealHarness(Harness):
    def __init__(self, url: str, fail_mode: str, signer: Signer) -> None:
        profile = Profile("real", True, fail_mode, "-", ())
        super().__init__(profile, signer, FakeRedis(), None)
        blumax_auth.configure_session_revocation(url, mode="enforce", fail_mode=fail_mode)  # the real redis.asyncio client
        import redis.asyncio as aioredis
        self.writer = aioredis.Redis.from_url(url, decode_responses=True)

    async def revoke(self, uid) -> None:  # exactly what Core writes (ISO now, 26 h TTL)
        await self.writer.set(f"session_revoked_at:{uid}", datetime.now(UTC).isoformat(), ex=26 * 3600)

    async def aclose(self) -> None:
        await self.writer.aclose()
        await blumax_auth.aclose_session_revocation()


@needs_container
@pytest.mark.parametrize("fail_mode", ["open", "closed"])
class TestRealRedis:
    async def _harness(self, c, fail_mode):
        return RealHarness(c.url, fail_mode, Signer())

    async def test_revoked_is_401_and_unrevoked_is_200(self, container_factory, fail_mode):
        c = container_factory("--save", "", "--appendonly", "no")
        h = await self._harness(c, fail_mode)
        try:
            token, uid, _ = h.token()
            other, _, _ = h.token()
            await h.revoke(uid)
            assert (await h.call(token)).status_code == 401
            assert (await h.call(other)).status_code == 200
        finally:
            await h.aclose()

    async def test_outage_then_recovery_with_aof_keeps_the_revocation(self, container_factory, fail_mode, monkeypatch):
        c = container_factory("--appendonly", "yes", "--appendfsync", "always")
        h = await self._harness(c, fail_mode)
        try:
            token, uid, _ = h.token()
            healthy, _, _ = h.token()
            await h.revoke(uid)
            c.stop()
            during = (await h.call(healthy)).status_code
            assert during == (401 if fail_mode == "closed" else 200), "outage: fail mode decides, never a 5xx"
            c.start()
            _breaker_window_passes(monkeypatch)
            assert (await h.call(token)).status_code == 401, "with AOF the marker survived the restart"
            assert (await h.call(healthy)).status_code == 200, "session recovery: no lasting lock-out"
        finally:
            await h.aclose()

    async def test_RESIDUAL_WINDOW_restart_without_persistence_revalidates_a_revoked_session(self, container_factory, fail_mode, monkeypatch):
        c = container_factory("--save", "", "--appendonly", "no")
        h = await self._harness(c, fail_mode)
        try:
            token, uid, _ = h.token()
            await h.revoke(uid)
            assert (await h.call(token)).status_code == 401
            c.stop()
            c.start()                                                    # the container's data is gone with the process
            assert c.cli("dbsize") == "0"
            # The first request after a restart meets the dead pooled connection: one failed read, so fail_mode answers
            # (open 200 / closed 401) and the breaker pauses Redis for its window. Measured, and why the next line waits it out.
            first = (await h.call(token)).status_code
            assert first == (401 if fail_mode == "closed" else 200)
            _breaker_window_passes(monkeypatch)
            assert (await h.call(token)).status_code == 200              # SEC-01 hazard, both modes
        finally:
            await h.aclose()

    async def test_RESIDUAL_WINDOW_flushall_revalidates_a_revoked_session(self, container_factory, fail_mode):
        c = container_factory("--save", "", "--appendonly", "no")
        h = await self._harness(c, fail_mode)
        try:
            token, uid, _ = h.token()
            await h.revoke(uid)
            assert (await h.call(token)).status_code == 401
            c.cli("flushall")
            assert (await h.call(token)).status_code == 200
        finally:
            await h.aclose()

    async def _fill(self, h, c, stop_on_error: bool) -> None:
        pad = "x" * 1024
        for i in range(60000):
            try:
                await h.writer.set(f"filler:{i}", pad)
            except Exception:
                if stop_on_error:
                    return
                raise
            if i % 500 == 0 and not stop_on_error and int(c.cli("info", "stats").split("evicted_keys:")[1].split()[0]) > 5000:
                return

    async def test_RESIDUAL_WINDOW_allkeys_lru_eviction_drops_the_marker(self, container_factory, fail_mode):
        c = container_factory("--maxmemory", "3mb", "--maxmemory-policy", "allkeys-lru", "--maxmemory-samples", "64",
                              "--save", "", "--appendonly", "no")
        h = await self._harness(c, fail_mode)
        try:
            token, uid, _ = h.token()
            await h.revoke(uid)
            assert (await h.call(token)).status_code == 401
            await self._fill(h, c, stop_on_error=False)
            assert c.cli("exists", f"session_revoked_at:{uid}") == "0", "the marker should have been evicted by the filler"
            assert (await h.call(token)).status_code == 200              # evicted marker == "not revoked" (RDS-001)
        finally:
            await h.aclose()

    async def test_noeviction_keeps_the_marker_under_memory_pressure(self, container_factory, fail_mode):
        """Why MSG-01's never-evicting instance matters: under noeviction, memory pressure fails new WRITES, never the marker."""
        c = container_factory("--maxmemory", "3mb", "--maxmemory-policy", "noeviction", "--save", "", "--appendonly", "no")
        h = await self._harness(c, fail_mode)
        try:
            token, uid, _ = h.token()
            await h.revoke(uid)
            await self._fill(h, c, stop_on_error=True)
            assert c.cli("exists", f"session_revoked_at:{uid}") == "1"
            assert (await h.call(token)).status_code == 401
        finally:
            await h.aclose()
