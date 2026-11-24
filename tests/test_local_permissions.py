"""0.6.0: access token v2 verification + local permission evaluation (off | shadow | local).

Real RS256 tokens (test_verification.Signer's key), a fake Core answering BOTH /api/v1/me/permissions and
/api/v1/authz/catalogue, a fake Redis for `authctx:authz_ver`, and a fake clock.
"""
from __future__ import annotations

import asyncio
import base64
import logging
import random
import uuid
from collections.abc import Iterable
from datetime import UTC, datetime, timedelta
from typing import Annotated

import httpx
import pytest
from fastapi import Depends, FastAPI
from jose import jwt
from test_verification import AUDIENCE, ISSUER, Signer

import blumax_auth
from blumax_auth import AuthContext, InvalidToken, JwksCache, TokenVerifier, metrics
from blumax_auth import session_revocation as sr
from blumax_auth.local_permissions import InvalidBitset, unpack_indexes

CORE = "http://core.test"
LOGGER = "blumax_auth.permissions"
PERMS = "/api/v1/me/permissions"
CATALOGUE = "/api/v1/authz/catalogue"

HELD = "opd.consultation.create"
NOT_HELD = "ipd.admission.create"
OTHER = "labs.result.validate"
UNKNOWN = "never.in.catalogue"

Held = Annotated[AuthContext, Depends(blumax_auth.require_permission(HELD))]
NotHeld = Annotated[AuthContext, Depends(blumax_auth.require_permission(NOT_HELD))]
Unknown = Annotated[AuthContext, Depends(blumax_auth.require_permission(UNKNOWN))]
NotHeldWarn = Annotated[AuthContext, Depends(blumax_auth.require_permission(NOT_HELD, mode="warn"))]


# ─── Core's encoder, copied VERBATIM from blumax-backend origin/dev (f2143e6) app/core/permission_index.py ──────────

class _CoreInvalidBitset(Exception):
    pass


def core_pack_indexes(indexes: Iterable[int]) -> str:
    """Set of indexes -> base64url (no padding) bitset, LSB-first within each byte, trailing zero bytes trimmed."""
    idx = set(indexes)
    if not idx:
        return ""
    if min(idx) < 0:
        raise _CoreInvalidBitset("negative index")
    raw = bytearray(max(idx) // 8 + 1)
    for i in idx:
        raw[i >> 3] |= 1 << (i & 7)
    return base64.urlsafe_b64encode(bytes(raw)).rstrip(b"=").decode("ascii")


# ─── Fakes ────────────────────────────────────────────────────────────────────

class FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


class FakeCore:
    """/me/permissions per bearer token (as Core answers per caller) + the catalogue."""

    def __init__(self) -> None:
        self.requests: list[httpx.Request] = []
        self.by_token: dict[str, tuple[int, object]] = {}
        self.catalogue_version = 3
        self.codes = {HELD: 0, NOT_HELD: 9, OTHER: 17, "x.deprecated": 20}
        self.catalogue_status = 200
        self.perm_status = 200
        self.delay = 0.0

    def calls(self, path: str) -> int:
        return sum(1 for r in self.requests if r.url.path == path)

    def grant(self, token: str, *codes: str) -> None:
        self.by_token[token] = (200, {"permissions": sorted(codes), "is_platform_admin": False})

    async def handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if self.delay:
            await asyncio.sleep(self.delay)
        if request.url.path == CATALOGUE:
            if self.catalogue_status != 200:
                return httpx.Response(self.catalogue_status, json={})
            entries = [
                {"idx": i, "code": c, "status": "deprecated" if c == "x.deprecated" else "active"}
                for c, i in sorted(self.codes.items(), key=lambda kv: kv[1])
            ]
            return httpx.Response(200, json={"version": self.catalogue_version, "since_version": None, "entries": entries})
        if self.perm_status != 200:
            return httpx.Response(self.perm_status, json={})
        token = request.headers.get("authorization", "").removeprefix("Bearer ")
        status, body = self.by_token.get(token, (401, {}))
        return httpx.Response(status, json=body)


class FakeRedis:
    def __init__(self, value: object = "7") -> None:
        self.value = value
        self.gets = 0
        self.fail: Exception | None = None

    async def get(self, key: str) -> object:
        assert key == "authctx:authz_ver"
        self.gets += 1
        if self.fail is not None:
            raise self.fail
        return self.value


# ─── Tokens ───────────────────────────────────────────────────────────────────

def mint(signer: Signer, *, v2: bool = True, codes: Iterable[str] = (HELD,), catalogue: dict[str, int] | None = None,
         cv: int | None = 3, authz_ver: int | None = 7, perm: object = "build", aud: object = None,
         typ_header: bool = True, **over: object) -> str:
    now = datetime.now(UTC)
    claims: dict[str, object] = {
        "iss": ISSUER, "aud": AUDIENCE, "sub": str(uuid.uuid4()), "type": "access", "jti": str(uuid.uuid4()),
        "iat": now, "exp": now + timedelta(minutes=10), "tid": str(uuid.uuid4()), "tsl": "apollo",
        "rol": "Doctor", "arc": "CLINICIAN", "fac": None, "pid": None, "prv": None, "adm": False,
    }
    headers = {"kid": signer.kid}
    if v2:
        index = catalogue or FakeCore().codes
        claims.update({"ver": 2, "nbf": now - timedelta(seconds=5), "sid": str(uuid.uuid4()),
                       "aud": aud if aud is not None else [AUDIENCE, "blumax-core", "blumax-opd"]})
        if perm == "build":
            if cv is not None:
                claims["perm"] = {"cv": cv, "b": core_pack_indexes(index[c] for c in codes)}
        elif perm is not None:
            claims["perm"] = perm
        if authz_ver is not None:
            claims["authz_ver"] = authz_ver
        if typ_header:
            headers["typ"] = "at+jwt"
    claims.update(over)
    return jwt.encode(claims, signer.pem, algorithm="RS256", headers=headers)


# ─── Fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    monkeypatch.delenv("PERMISSION_LOCAL_MODE", raising=False)
    monkeypatch.delenv("PERMISSION_AUTHZ_VER_REDIS_URL", raising=False)
    monkeypatch.delenv("PERMISSION_AUTHZ_VER_CACHE_SECONDS", raising=False)
    metrics.reset_metrics()
    sr.reset_session_revocation()
    yield
    metrics.reset_metrics()
    sr.reset_session_revocation()
    blumax_auth.reset_permissions()
    blumax_auth.reset()


@pytest.fixture
def signer() -> Signer:
    return Signer()


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def core() -> FakeCore:
    return FakeCore()


@pytest.fixture
def redis() -> FakeRedis:
    return FakeRedis()


def configure(core: FakeCore, clock: FakeClock, redis: FakeRedis | None, **over: object) -> None:
    kwargs: dict[str, object] = dict(
        core_url=CORE, ttl_seconds=30.0, timeout_seconds=2.0, transport=httpx.MockTransport(lambda r: core.handle(r)),
        clock=clock, authz_ver_redis=redis,
    )
    kwargs.update(over)
    blumax_auth.configure_permissions(**kwargs)  # type: ignore[arg-type]


def build_app(signer: Signer, **configure_kwargs: object) -> FastAPI:
    blumax_auth.reset()
    blumax_auth.configure(jwks_url="http://unused.invalid/jwks.json", issuer=ISSUER, audience=AUDIENCE, **configure_kwargs)  # type: ignore[arg-type]
    blumax_auth.jwks_cache().seed(signer.jwks())
    app = FastAPI()
    blumax_auth.install_error_handler(app)

    @app.get("/held")
    async def held(ctx: Held) -> dict:
        return {"ok": True}

    @app.get("/not-held")
    async def not_held(ctx: NotHeld) -> dict:
        return {"ok": True}

    @app.get("/unknown")
    async def unknown(ctx: Unknown) -> dict:
        return {"ok": True}

    @app.get("/not-held-warn")
    async def not_held_warn(ctx: NotHeldWarn) -> dict:
        return {"ok": True}

    return app


@pytest.fixture
async def client(signer):
    app = build_app(signer)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as c:
        yield c


async def settle() -> None:
    """Wait for the background catalogue preload (0.6.1), if one is in flight."""
    local = getattr(blumax_auth.permissions._checker, "local", None)
    task = getattr(local, "_cat_task", None)
    if task is not None:
        await asyncio.wait([task])
    await asyncio.sleep(0)


def slow_catalogue(core: FakeCore, seconds: float) -> None:
    """Delay only Core's catalogue answer (not /me/permissions)."""
    inner = core.handle

    async def handle(request: httpx.Request) -> httpx.Response:
        if request.url.path == CATALOGUE:
            core.requests.append(request)
            # MockTransport does not enforce httpx timeouts: honour the request's read timeout here, as a real socket would
            read = (request.extensions.get("timeout") or {}).get("read")
            if read is not None and seconds > read:
                await asyncio.sleep(read)
                raise httpx.ReadTimeout("catalogue too slow", request=request)
            await asyncio.sleep(seconds)
            core.requests.remove(request)  # inner records it again
        return await inner(request)

    core.handle = handle  # type: ignore[method-assign]


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def shadow_records(caplog, event: str = "permission_local_shadow") -> list[logging.LogRecord]:
    return [r for r in caplog.records if r.name == LOGGER and r.getMessage().split(" ", 1)[0] == event]


def local_records(caplog) -> list[logging.LogRecord]:
    return [r for r in caplog.records if r.getMessage().startswith("permission_local") or r.getMessage().startswith("permission_catalogue")]


# ─── Bitset: byte-for-byte Core's format ──────────────────────────────────────

class TestBitset:
    @pytest.mark.parametrize("indexes", [set(), {0}, {7}, {8}, {0, 9}, {398}, {0, 1, 2, 3, 4, 5, 6, 7, 8}, set(range(480))])
    def test_round_trip_with_cores_encoder(self, indexes):
        assert unpack_indexes(core_pack_indexes(indexes)) == indexes

    def test_random_sets_round_trip(self):
        rng = random.Random(20261124)
        for _ in range(300):
            s = set(rng.sample(range(600), rng.randint(0, 80)))
            assert unpack_indexes(core_pack_indexes(s)) == s

    def test_known_vectors(self):
        # byte0 = bit0 -> 0x01, byte1 = bit(9-8)=1 -> 0x02 ; LSB first, no padding, trailing zero bytes trimmed
        assert core_pack_indexes({0, 9}) == "AQI"
        assert unpack_indexes("AQI") == {0, 9}
        assert unpack_indexes("") == set()
        assert unpack_indexes("gA") == {7}

    def test_garbage_is_invalid(self):
        with pytest.raises(InvalidBitset):
            unpack_indexes("a")  # one base64 char can never be a byte


# ─── Verification: dual profile ───────────────────────────────────────────────

class TestDualProfileVerify:
    @pytest.fixture
    def verifier(self, signer) -> TokenVerifier:
        cache = JwksCache("http://unused.invalid/jwks.json")
        cache.seed(signer.jwks())
        return TokenVerifier(cache, issuer=ISSUER, audience=AUDIENCE)

    async def test_v2_aud_list_containing_blumax_is_accepted(self, signer, verifier):
        ctx = await verifier.verify(mint(signer))
        assert ctx.archetype == "CLINICIAN" and not ctx.is_service

    async def test_v2_aud_list_without_blumax_is_refused(self, signer, verifier):
        with pytest.raises(InvalidToken):
            await verifier.verify(mint(signer, aud=["blumax-core", "blumax-opd"]))

    async def test_v1_still_verifies(self, signer, verifier):
        ctx = await verifier.verify(mint(signer, v2=False))
        assert ctx.tenant_id is not None

    async def test_nbf_in_the_future_is_refused(self, signer, verifier):
        future = datetime.now(UTC) + timedelta(minutes=5)  # beyond the 30 s leeway
        with pytest.raises(InvalidToken):
            await verifier.verify(mint(signer, nbf=future))

    async def test_nbf_within_leeway_is_accepted(self, signer, verifier):
        await verifier.verify(mint(signer, nbf=datetime.now(UTC) + timedelta(seconds=10)))

    async def test_service_audience_default_none_counts_nothing(self, signer, verifier):
        await verifier.verify(mint(signer, aud=[AUDIENCE]))
        assert metrics.audience_snapshot() == 0

    async def test_service_audience_missing_is_accepted_counted_and_logged_once(self, signer, caplog):
        cache = JwksCache("http://unused.invalid/jwks.json")
        cache.seed(signer.jwks())
        v = TokenVerifier(cache, issuer=ISSUER, audience=AUDIENCE, service_audience="blumax-labs")
        with caplog.at_level(logging.WARNING, logger="blumax_auth.verify"):
            await v.verify(mint(signer))                     # aud has blumax-opd, not blumax-labs
            await v.verify(mint(signer))
            await v.verify(mint(signer, aud=[AUDIENCE, "blumax-labs"]))
            await v.verify(mint(signer, v2=False))           # v1: never checked
        assert metrics.audience_snapshot() == 2
        assert len([r for r in caplog.records if r.getMessage() == "token_service_audience_missing"]) == 1

    async def test_configure_passes_service_audience(self, signer):
        build_app(signer, service_audience="blumax-labs")
        await blumax_auth.verifier().verify(mint(signer))
        assert metrics.audience_snapshot() == 1


# ─── Mode "off": nothing changes ──────────────────────────────────────────────

class TestOff:
    @pytest.mark.parametrize("v2", [False, True])
    async def test_off_is_exactly_the_core_path(self, client, signer, core, clock, redis, caplog, v2):
        configure(core, clock, redis)  # local_mode omitted, env unset -> off
        token = mint(signer, v2=v2, codes=(HELD,))
        core.grant(token, HELD)
        with caplog.at_level(logging.DEBUG):
            assert (await client.get("/held", headers=bearer(token))).status_code == 200
            assert (await client.get("/held", headers=bearer(token))).status_code == 200  # cached
            assert (await client.get("/not-held", headers=bearer(token))).status_code == 403
        assert core.calls(PERMS) == 1 and core.calls(CATALOGUE) == 0 and redis.gets == 0
        assert metrics.local_snapshot() == {}
        assert local_records(caplog) == []
        assert blumax_auth.permissions._checker.local is None

    async def test_explicit_off_and_env_off(self, core, clock, redis, monkeypatch):
        configure(core, clock, redis, local_mode="off")
        assert blumax_auth.permissions._checker.local is None
        monkeypatch.setenv("PERMISSION_LOCAL_MODE", "off")
        configure(core, clock, redis)
        assert blumax_auth.permissions._checker.local is None

    async def test_env_selects_shadow(self, core, clock, redis, monkeypatch):
        monkeypatch.setenv("PERMISSION_LOCAL_MODE", "Shadow")
        configure(core, clock, redis)
        assert blumax_auth.permissions._checker.local_mode == "shadow"

    def test_invalid_mode_raises(self, core, clock, redis, monkeypatch):
        with pytest.raises(ValueError):
            configure(core, clock, redis, local_mode="on")
        monkeypatch.setenv("PERMISSION_LOCAL_MODE", "yes")
        with pytest.raises(ValueError):
            configure(core, clock, redis)


# ─── Mode "shadow": Core decides, local compared ─────────────────────────────

class TestShadow:
    @pytest.fixture(autouse=True)
    def _shadow(self, core, clock, redis):
        configure(core, clock, redis, local_mode="shadow")

    async def _ask(self, client, path: str, token: str) -> int:
        return (await client.get(path, headers=bearer(token))).status_code

    async def test_match_counted_not_logged(self, client, signer, core, redis, caplog):
        token = mint(signer, codes=(HELD,))
        core.grant(token, HELD)
        with caplog.at_level(logging.INFO, logger=LOGGER):
            assert await self._ask(client, "/held", token) == 200
            assert await self._ask(client, "/not-held", token) == 403
        assert metrics.local_snapshot() == {"match": 2}
        assert shadow_records(caplog) == []
        assert core.calls(PERMS) == 1 and core.calls(CATALOGUE) == 1 and redis.gets == 1

    async def test_mismatch_logged_and_core_still_decides(self, client, signer, core, caplog):
        token = mint(signer, codes=())                     # token: holds nothing
        core.grant(token, HELD)                            # Core: holds HELD
        with caplog.at_level(logging.INFO, logger=LOGGER):
            assert await self._ask(client, "/held", token) == 200  # Core's answer wins
        assert metrics.local_snapshot() == {"mismatch": 1}
        [rec] = shadow_records(caplog)
        assert rec.levelno == logging.WARNING
        assert (rec.outcome, rec.core_decision, rec.local_decision, rec.permission, rec.route) == (
            "mismatch", "allow", "deny", HELD, "/held")

    async def test_mismatch_log_is_rate_limited(self, client, signer, core, clock, caplog):
        with caplog.at_level(logging.INFO, logger=LOGGER):
            for _ in range(3):
                token = mint(signer, codes=())
                core.grant(token, HELD)
                await self._ask(client, "/held", token)
            clock.advance(61)
            token = mint(signer, codes=())
            core.grant(token, HELD)
            await self._ask(client, "/held", token)
        recs = shadow_records(caplog)
        assert len(recs) == 2 and recs[1].suppressed == 2
        assert metrics.local_snapshot() == {"mismatch": 4}

    @pytest.mark.parametrize(("kwargs", "reason"), [
        ({"perm": None}, "no_perm"),
        ({"perm": {"cv": "3", "b": "AQ"}}, "no_perm"),
        ({"authz_ver": None}, "no_authz_ver"),
        ({"authz_ver": 6}, "authz_ver_stale"),
        ({"authz_ver": 8}, "authz_ver_stale"),   # != not <: a flushed-and-rebumped Redis can be BELOW the token
        ({"perm": {"cv": 3, "b": core_pack_indexes({0, 40})}}, "invalid_bitset"),
        ({"perm": {"cv": 3, "b": "a"}}, "invalid_bitset"),
    ])
    async def test_token_fallbacks(self, client, signer, core, caplog, kwargs, reason):
        token = mint(signer, **kwargs)
        core.grant(token, HELD)
        with caplog.at_level(logging.INFO, logger=LOGGER):
            assert await self._ask(client, "/held", token) == 200
        assert metrics.local_snapshot() == {f"fallback:{reason}": 1}
        [rec] = shadow_records(caplog)
        assert rec.levelno == logging.INFO and rec.reason == reason and rec.outcome == "fallback"

    async def test_unknown_code(self, client, signer, core):
        token = mint(signer)
        core.grant(token, HELD, UNKNOWN)
        assert await self._ask(client, "/unknown", token) == 200
        assert metrics.local_snapshot() == {"fallback:unknown_code": 1}

    async def test_redis_down(self, client, signer, core, redis):
        redis.fail = ConnectionError("down")
        token = mint(signer)
        core.grant(token, HELD)
        assert await self._ask(client, "/held", token) == 200
        assert metrics.local_snapshot() == {"fallback:authz_ver_unavailable": 1}
        await settle()
        assert core.calls(CATALOGUE) == 1  # 0.6.1: the preload starts before the freshness check, so it still loads

    async def test_redis_key_absent(self, client, signer, core, redis):
        redis.value = None
        token = mint(signer, authz_ver=0)
        core.grant(token, HELD)
        await self._ask(client, "/held", token)
        assert metrics.local_snapshot() == {"fallback:authz_ver_unset": 1}

    async def test_no_redis_configured(self, client, signer, core, clock):
        configure(core, clock, None, local_mode="shadow")
        token = mint(signer)
        core.grant(token, HELD)
        await self._ask(client, "/held", token)
        assert metrics.local_snapshot() == {"fallback:authz_ver_not_configured": 1}

    async def test_reuses_the_session_revocation_redis(self, client, signer, core, clock):
        configure(core, clock, None, local_mode="shadow")
        shared = FakeRedis("7")
        sr._checker = sr._Checker(shared, mode="warn")  # what configure_session_revocation(url) builds
        token = mint(signer)
        core.grant(token, HELD)
        await self._ask(client, "/held", token)
        assert shared.gets == 1 and metrics.local_snapshot() == {"match": 1}

    async def test_catalogue_fetch_failure_backs_off(self, client, signer, core, clock):
        core.catalogue_status = 503
        for _ in range(3):
            token = mint(signer)
            core.grant(token, HELD)
            assert await self._ask(client, "/held", token) == 200
        assert metrics.local_snapshot() == {"fallback:catalogue_unavailable": 3}
        assert core.calls(CATALOGUE) == 1  # backed off
        core.catalogue_status = 200
        clock.advance(11)
        token = mint(signer)
        core.grant(token, HELD)
        await self._ask(client, "/held", token)
        assert core.calls(CATALOGUE) == 2 and metrics.local_snapshot()["match"] == 1

    async def test_malformed_catalogue(self, client, signer, core):
        core.codes = {HELD: 0, NOT_HELD: 0}  # duplicate idx
        token = mint(signer, catalogue={HELD: 0, NOT_HELD: 9})
        core.grant(token, HELD)
        await self._ask(client, "/held", token)
        assert metrics.local_snapshot() == {"fallback:catalogue_unavailable": 1}

    async def test_newer_cv_refetches_the_catalogue(self, client, signer, core):
        t1 = mint(signer, cv=3)
        core.grant(t1, HELD)
        await self._ask(client, "/held", t1)
        assert core.calls(CATALOGUE) == 1
        core.catalogue_version = 4
        core.codes = {**core.codes, "new.code": 25}
        t2 = mint(signer, cv=4, codes=(HELD, "new.code"), catalogue=core.codes)
        core.grant(t2, HELD)
        core.delay = 0.05  # the refetch is in the background: this request does not wait for it
        await self._ask(client, "/held", t2)
        await settle()
        core.delay = 0.0
        assert core.calls(CATALOGUE) == 2
        assert metrics.local_snapshot() == {"match": 1, "fallback:catalogue_behind": 1}
        await self._ask(client, "/held", t2)
        assert metrics.local_snapshot() == {"match": 2, "fallback:catalogue_behind": 1}
        # an older cv decodes against the newer catalogue without another fetch
        t3 = mint(signer, cv=3)
        core.grant(t3, HELD)
        await self._ask(client, "/held", t3)
        assert core.calls(CATALOGUE) == 2

    async def test_newer_cv_but_core_still_behind(self, client, signer, core, clock):
        t1 = mint(signer, cv=5)
        core.grant(t1, HELD)
        await self._ask(client, "/held", t1)
        t2 = mint(signer, cv=5)
        core.grant(t2, HELD)
        await self._ask(client, "/held", t2)
        assert metrics.local_snapshot() == {"fallback:catalogue_behind": 2}
        assert core.calls(CATALOGUE) == 1  # not refetched for every request

    async def test_v1_and_service_tokens_counted_not_logged(self, client, signer, core, redis, caplog):
        v1 = mint(signer, v2=False)
        core.grant(v1, HELD)
        svc = mint(signer, type="service")
        core.grant(svc, HELD)
        with caplog.at_level(logging.INFO, logger=LOGGER):
            await self._ask(client, "/held", v1)
            await self._ask(client, "/held", svc)
        assert metrics.local_snapshot() == {"fallback:v1_token": 1, "fallback:service_token": 1}
        assert shadow_records(caplog) == [] and redis.gets == 0 and core.calls(CATALOGUE) == 0

    async def test_core_failure_unchanged_and_nothing_compared(self, client, signer, core):
        core.perm_status = 500
        token = mint(signer)
        assert await self._ask(client, "/held", token) == 503
        assert metrics.local_snapshot() == {}

    async def test_platform_admin_unchanged(self, client, signer, core, redis):
        token = mint(signer, adm=True)
        assert await self._ask(client, "/not-held", token) == 200
        assert core.requests == [] and redis.gets == 0

    async def test_authz_ver_cached_at_most_the_window(self, client, signer, core, clock, redis):
        for _ in range(3):
            token = mint(signer)
            core.grant(token, HELD)
            await self._ask(client, "/held", token)
        assert redis.gets == 1
        clock.advance(2.1)
        token = mint(signer)
        core.grant(token, HELD)
        await self._ask(client, "/held", token)
        assert redis.gets == 2

    def test_cache_seconds_clamped_to_5(self, core, clock, redis):
        configure(core, clock, redis, local_mode="shadow", authz_ver_cache_seconds=60)
        assert blumax_auth.permissions._checker.local._ver_ttl == 5.0


# ─── Mode "local": the token decides when it can ──────────────────────────────

class TestLocal:
    @pytest.fixture(autouse=True)
    def _local(self, core, clock, redis):
        configure(core, clock, redis, local_mode="local")

    async def test_grant_and_deny_from_the_token_without_asking_core(self, client, signer, core):
        token = mint(signer, codes=(HELD,))
        assert (await client.get("/held", headers=bearer(token))).status_code == 200
        r = await client.get("/not-held", headers=bearer(token))
        assert r.status_code == 403
        assert core.calls(PERMS) == 0 and core.calls(CATALOGUE) == 1
        assert metrics.local_snapshot() == {"local_allow": 1, "local_deny": 1}

    async def test_deprecated_code_still_decodes(self, client, signer, core):
        token = mint(signer, codes=("x.deprecated",))
        configure(core, FakeClock(), FakeRedis(), local_mode="local")
        ok = await blumax_auth.check_permission(await blumax_auth.verifier().verify(token), token, "x.deprecated")
        assert ok is True and core.calls(PERMS) == 0

    async def test_warn_mode_line_carries_source_local(self, client, signer, core, caplog):
        token = mint(signer, codes=(HELD,))
        with caplog.at_level(logging.INFO, logger=LOGGER):
            assert (await client.get("/not-held-warn", headers=bearer(token))).status_code == 200
        [rec] = [r for r in caplog.records if r.getMessage() == "permission_check"]
        assert rec.decision == "would_deny" and rec.source == "local"

    @pytest.mark.parametrize(("kwargs", "reason"), [
        ({"perm": None}, "no_perm"),
        ({"authz_ver": None}, "no_authz_ver"),
        ({"authz_ver": 1}, "authz_ver_stale"),
    ])
    async def test_fallbacks_ask_core(self, client, signer, core, caplog, kwargs, reason):
        token = mint(signer, codes=(), **kwargs)   # the token says "no" ...
        core.grant(token, HELD)                    # ... but it cannot be trusted; Core says yes
        with caplog.at_level(logging.INFO, logger=LOGGER):
            assert (await client.get("/held", headers=bearer(token))).status_code == 200
        assert core.calls(PERMS) == 1
        assert metrics.local_snapshot() == {f"fallback:{reason}": 1}
        [rec] = shadow_records(caplog, "permission_local_fallback")
        assert rec.reason == reason

    async def test_fallback_never_grants_when_core_denies(self, client, signer, core):
        token = mint(signer, codes=(HELD,), authz_ver=1)  # token says yes, but is stale
        core.grant(token)                                 # Core says no
        assert (await client.get("/held", headers=bearer(token))).status_code == 403

    async def test_redis_down_and_catalogue_down_ask_core(self, client, signer, core, redis):
        redis.fail = TimeoutError()
        token = mint(signer)
        core.grant(token, HELD)
        assert (await client.get("/held", headers=bearer(token))).status_code == 200
        assert core.calls(PERMS) == 1
        redis.fail = None
        configure(core, FakeClock(), redis, local_mode="local")
        core.catalogue_status = 500
        token2 = mint(signer)
        core.grant(token2, HELD)
        assert (await client.get("/held", headers=bearer(token2))).status_code == 200
        assert core.calls(PERMS) == 2

    async def test_unknown_code_asks_core(self, client, signer, core):
        token = mint(signer)
        core.grant(token)
        assert (await client.get("/unknown", headers=bearer(token))).status_code == 403
        assert core.calls(PERMS) == 1 and metrics.local_snapshot() == {"fallback:unknown_code": 1}

    async def test_v1_token_unchanged(self, client, signer, core):
        token = mint(signer, v2=False)
        core.grant(token, HELD)
        assert (await client.get("/held", headers=bearer(token))).status_code == 200
        assert (await client.get("/not-held", headers=bearer(token))).status_code == 403
        assert core.calls(PERMS) == 1 and core.calls(CATALOGUE) == 0

    async def test_service_token_uses_core(self, client, signer, core):
        token = mint(signer, type="service")
        core.grant(token, HELD)
        assert (await client.get("/held", headers=bearer(token))).status_code == 200
        assert core.calls(PERMS) == 1

    async def test_authz_bump_is_seen_after_the_cache_window(self, client, signer, core, clock, redis):
        token = mint(signer, codes=(HELD,))
        core.grant(token)  # Core already says no (role edited); the token still says yes
        assert (await client.get("/held", headers=bearer(token))).status_code == 200  # local, within the window
        redis.value = "8"   # the role edit's bump
        clock.advance(2.1)
        assert (await client.get("/held", headers=bearer(token))).status_code == 403  # stale -> Core -> no
        assert core.calls(PERMS) == 1

    async def test_concurrent_first_requests_share_one_catalogue_fetch_and_one_redis_read(self, client, signer, core, redis):
        slow_catalogue(core, 0.3)
        tokens = [mint(signer) for _ in range(10)]
        for t in tokens:
            core.grant(t, HELD)
        rs = await asyncio.gather(*(client.get("/held", headers=bearer(t)) for t in tokens))
        assert {r.status_code for r in rs} == {200}
        # ONE background fetch; nobody waited for it -- all ten asked Core while it loaded
        assert core.calls(CATALOGUE) == 1 and redis.gets == 1 and core.calls(PERMS) == 10
        assert metrics.local_snapshot() == {"fallback:catalogue_loading": 10}
        await settle()
        assert (await client.get("/held", headers=bearer(mint(signer)))).status_code == 200
        assert core.calls(CATALOGUE) == 1 and core.calls(PERMS) == 10
        assert metrics.local_snapshot()["local_allow"] == 1

    async def test_catalogue_fetched_with_the_callers_token_and_tenant(self, client, signer, core):
        token = mint(signer)
        await client.get("/held", headers=bearer(token))
        [req] = [r for r in core.requests if r.url.path == CATALOGUE]
        claims = jwt.get_unverified_claims(token)
        assert req.headers["authorization"] == f"Bearer {token}" and req.headers["x-tenant-id"] == claims["tid"]

    async def test_check_permission_local(self, signer, core):
        token = mint(signer, codes=(HELD,))
        build_app(signer)
        ctx = await blumax_auth.verifier().verify(token)
        assert await blumax_auth.check_permission(ctx, token, HELD) is True
        assert await blumax_auth.check_permission(ctx, token, NOT_HELD) is False
        assert core.calls(PERMS) == 0

    async def test_token_must_match_the_context(self, signer, core):
        build_app(signer)
        token = mint(signer)
        other = mint(signer)
        core.grant(other, HELD)
        ctx = await blumax_auth.verifier().verify(token)
        # a caller passing a different token than the verified one is never answered from that token
        assert await blumax_auth.check_permission(ctx, other, HELD) is True
        assert metrics.local_snapshot() == {"fallback:token_unreadable": 1} and core.calls(PERMS) == 1


class TestLocalAdminRoutes:
    async def test_admin_route_always_asks_core_in_local_mode(self, signer, core, clock, redis, caplog):
        configure(core, clock, redis, local_mode="local")
        build_app(signer)
        token = mint(signer, codes=(HELD,))
        core.grant(token)  # Core says no
        ctx = await blumax_auth.verifier().verify(token)
        with caplog.at_level(logging.INFO, logger=LOGGER):
            assert await blumax_auth.check_permission(ctx, token, HELD, admin=True) is False
        assert core.calls(PERMS) == 1 and redis.gets == 0
        assert metrics.local_snapshot() == {"fallback:admin_route": 1}
        assert shadow_records(caplog, "permission_local_fallback") == []

    async def test_local_decisions_are_not_logged(self, signer, core, clock, redis, caplog):
        configure(core, clock, redis, local_mode="local")
        build_app(signer)
        token = mint(signer, codes=(HELD,))
        ctx = await blumax_auth.verifier().verify(token)
        with caplog.at_level(logging.INFO, logger=LOGGER):
            assert await blumax_auth.check_permission(ctx, token, HELD) is True
            assert await blumax_auth.check_permission(ctx, token, NOT_HELD) is False
        assert [r for r in caplog.records if r.getMessage().startswith("permission_local")] == []


# ─── 0.6.1: catalogue timeout, background preload, reasons in the message text ─────────────────────────────────────

class TestCatalogueTimeout:
    def _local(self):
        return blumax_auth.permissions._checker.local

    def test_default_is_10_and_independent_of_the_check_timeout(self, core, clock, redis):
        configure(core, clock, redis, local_mode="shadow", timeout_seconds=3.0)
        assert self._local()._timeout == 10.0
        assert self._local()._http().timeout.read == 10.0
        assert blumax_auth.permissions._checker._timeout == 3.0

    def test_explicit_and_env(self, core, clock, redis, monkeypatch):
        configure(core, clock, redis, local_mode="shadow", catalogue_timeout_seconds=4.5)
        assert self._local()._timeout == 4.5
        monkeypatch.setenv("PERMISSION_CATALOGUE_TIMEOUT_SECONDS", "12")
        configure(core, clock, redis, local_mode="shadow")
        assert self._local()._timeout == 12.0
        monkeypatch.setenv("PERMISSION_CATALOGUE_TIMEOUT_SECONDS", "nonsense")
        configure(core, clock, redis, local_mode="shadow")
        assert self._local()._timeout == 10.0

    def test_capped_at_30_and_must_be_positive(self, core, clock, redis, caplog):
        with caplog.at_level(logging.WARNING, logger=LOGGER):
            configure(core, clock, redis, local_mode="local", catalogue_timeout_seconds=120)
        assert self._local()._timeout == 30.0
        assert any(r.getMessage().startswith("permission_catalogue_timeout_clamped configured=120") for r in caplog.records)
        with pytest.raises(ValueError):
            configure(core, clock, redis, local_mode="local", catalogue_timeout_seconds=0)

    def test_off_reads_nothing_and_logs_nothing(self, core, clock, redis, monkeypatch, caplog):
        monkeypatch.setenv("PERMISSION_CATALOGUE_TIMEOUT_SECONDS", "nonsense")
        with caplog.at_level(logging.DEBUG):
            configure(core, clock, redis, catalogue_timeout_seconds=999)  # ignored: local_mode off
        assert blumax_auth.permissions._checker.local is None
        assert [r for r in caplog.records if r.name == LOGGER] == []

    async def test_slow_catalogue_beyond_the_check_timeout_still_loads(self, client, signer, core, clock, redis):
        configure(core, clock, redis, local_mode="local", timeout_seconds=0.05, catalogue_timeout_seconds=2.0)
        slow_catalogue(core, 0.2)  # > the 0.05 s check timeout, < the 2 s catalogue timeout
        token = mint(signer)
        core.grant(token, HELD)
        assert (await client.get("/held", headers=bearer(token))).status_code == 200  # Core, while loading
        await settle()
        assert self._local()._catalogue is not None
        assert (await client.get("/held", headers=bearer(mint(signer)))).status_code == 200
        assert metrics.local_snapshot() == {"fallback:catalogue_loading": 1, "local_allow": 1}

    async def test_catalogue_timeout_fails_backs_off_and_says_why_in_the_message(self, client, signer, core, clock, redis, caplog):
        configure(core, clock, redis, local_mode="local", catalogue_timeout_seconds=0.05)
        slow_catalogue(core, 0.3)
        token = mint(signer)
        core.grant(token, HELD)
        with caplog.at_level(logging.INFO, logger=LOGGER):
            assert (await client.get("/held", headers=bearer(token))).status_code == 200
            await settle()
            assert (await client.get("/held", headers=bearer(token))).status_code == 200
        msgs = [r.getMessage() for r in caplog.records]
        assert any(m.startswith("permission_catalogue_fetch_failed reason=ReadTimeout back_off=True") for m in msgs), msgs
        assert metrics.local_snapshot() == {"fallback:catalogue_loading": 1, "fallback:catalogue_unavailable": 1}
        assert core.calls(CATALOGUE) == 1  # backed off: not refetched by the second request


class TestBackgroundPreload:
    async def test_first_request_never_waits_for_the_catalogue(self, client, signer, core, clock, redis):
        configure(core, clock, redis, local_mode="local")
        slow_catalogue(core, 0.5)
        token = mint(signer)
        core.grant(token, HELD)
        loop = asyncio.get_running_loop()
        started = loop.time()
        assert (await client.get("/held", headers=bearer(token))).status_code == 200
        assert loop.time() - started < 0.4
        assert metrics.local_snapshot() == {"fallback:catalogue_loading": 1}
        assert core.calls(PERMS) == 1
        await settle()
        assert blumax_auth.permissions._checker.local._catalogue is not None

    async def test_shadow_request_never_waits_for_the_catalogue(self, client, signer, core, clock, redis):
        configure(core, clock, redis, local_mode="shadow")
        slow_catalogue(core, 0.5)
        token = mint(signer)
        core.grant(token, HELD)
        loop = asyncio.get_running_loop()
        started = loop.time()
        assert (await client.get("/held", headers=bearer(token))).status_code == 200
        assert loop.time() - started < 0.4
        assert metrics.local_snapshot() == {"fallback:catalogue_loading": 1}
        await settle()
        token2 = mint(signer)
        core.grant(token2, HELD)
        await client.get("/held", headers=bearer(token2))
        assert metrics.local_snapshot() == {"fallback:catalogue_loading": 1, "match": 1}

    async def test_preload_starts_even_when_freshness_falls_back(self, client, signer, core, clock, redis):
        configure(core, clock, redis, local_mode="local")
        token = mint(signer, authz_ver=6)  # stale
        core.grant(token, HELD)
        await client.get("/held", headers=bearer(token))
        await settle()
        assert core.calls(CATALOGUE) == 1
        assert metrics.local_snapshot() == {"fallback:authz_ver_stale": 1}

    async def test_v1_and_service_tokens_do_not_start_a_preload(self, client, signer, core, clock, redis):
        configure(core, clock, redis, local_mode="local")
        for token in (mint(signer, v2=False), mint(signer, type="service")):
            core.grant(token, HELD)
            await client.get("/held", headers=bearer(token))
        await settle()
        assert core.calls(CATALOGUE) == 0

    async def test_unexpected_preload_error_is_logged_and_backed_off(self, client, signer, core, clock, redis, caplog):
        configure(core, clock, redis, local_mode="local")

        async def boom(*a, **k):
            raise RuntimeError("bug")

        blumax_auth.permissions._checker.local._fetch_catalogue = boom
        token = mint(signer)
        core.grant(token, HELD)
        with caplog.at_level(logging.INFO, logger=LOGGER):
            assert (await client.get("/held", headers=bearer(token))).status_code == 200
            await settle()
        assert any(r.getMessage().startswith("permission_catalogue_fetch_failed reason=error RuntimeError") for r in caplog.records)
        assert blumax_auth.permissions._checker.local._cat_blocked_until > clock()

    async def test_aclose_cancels_an_inflight_preload(self, client, signer, core, clock, redis):
        configure(core, clock, redis, local_mode="local")
        slow_catalogue(core, 5)
        token = mint(signer)
        core.grant(token, HELD)
        await client.get("/held", headers=bearer(token))
        task = blumax_auth.permissions._checker.local._cat_task
        assert task is not None and not task.done()
        await blumax_auth.aclose_permissions()
        await asyncio.sleep(0)
        assert task.cancelled()


class TestReasonInMessageText:
    async def test_shadow_fallback_line_carries_the_reason_in_the_text(self, client, signer, core, clock, redis, caplog):
        configure(core, clock, redis, local_mode="shadow")
        token = mint(signer, authz_ver=6)
        core.grant(token, HELD)
        with caplog.at_level(logging.INFO, logger=LOGGER):
            await client.get("/held", headers=bearer(token))
        [rec] = shadow_records(caplog)
        assert rec.getMessage() == (
            f"permission_local_shadow outcome=fallback reason=authz_ver_stale code={HELD} route=/held core=allow "
            "catalogue_version=3 token_authz_ver=6 current_authz_ver=7"
        )
        assert (rec.outcome, rec.reason, rec.permission, rec.route) == ("fallback", "authz_ver_stale", HELD, "/held")

    async def test_mismatch_line_carries_both_decisions(self, client, signer, core, clock, redis, caplog):
        configure(core, clock, redis, local_mode="shadow")
        warm = mint(signer)
        core.grant(warm, HELD)
        await client.get("/held", headers=bearer(warm))
        await settle()
        token = mint(signer, codes=())
        core.grant(token, HELD)
        with caplog.at_level(logging.INFO, logger=LOGGER):
            await client.get("/held", headers=bearer(token))
        [rec] = shadow_records(caplog)
        assert rec.getMessage().startswith(f"permission_local_shadow outcome=mismatch reason=- code={HELD} route=/held core=allow local=deny")

    async def test_local_fallback_line_and_loading_reason(self, client, signer, core, clock, redis, caplog):
        configure(core, clock, redis, local_mode="local")
        slow_catalogue(core, 0.2)
        token = mint(signer)
        core.grant(token, HELD)
        with caplog.at_level(logging.INFO, logger=LOGGER):
            await client.get("/held", headers=bearer(token))
        [rec] = shadow_records(caplog, "permission_local_fallback")
        assert rec.getMessage().startswith(f"permission_local_fallback outcome=fallback reason=catalogue_loading code={HELD} route=/held")
        await settle()
