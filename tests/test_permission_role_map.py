"""0.6.0 role map: permissions from the token's `rid` + `pv` and a per-process role -> codes map, with revocation still bounded.

A small in-memory "Core" holds the truth (tenant pv, grants gv, role codes, members) and answers BOTH endpoints the library calls:
GET /api/v1/me/permissions (the old path, live) and GET /api/v1/identity/role-permissions (the role map). `publish()` copies its versions
into the fake Redis the way Core's publisher does (ZADD GT on role:perms:ver). Time is a fake clock.

Revocation proof (the owner rule: a revoked role / permission stops within ~30 s): a role edit, a membership removal and a deactivation each
stop access within the version cache window (5 s) for a token minted BEFORE the change; Redis down, a revoked session, missing claims, an
unknown role, or Core's database ahead of Redis all fall back to Core's own answer -- never a grant on doubt.
"""
from __future__ import annotations

import hashlib
import json
import uuid
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from test_permissions import CODE, CORE, FakeClock
from test_verification import AUDIENCE, ISSUER, Signer

import blumax_auth
import blumax_auth.session_revocation as sr
from blumax_auth import AuthContext, metrics
from blumax_auth import permissions as perm
from blumax_auth.errors import Forbidden, InvalidToken
from blumax_auth.permissions import MAX_VERSION_CACHE_SECONDS, _Checker

OTHER = "opd.visit.view"


class FakeRedis:
    """GET (revocation markers) + ZMSCORE / ZADD GT (versions)."""

    def __init__(self) -> None:
        self.store: dict[str, str] = {}
        self.zsets: dict[str, dict[str, float]] = {}
        self.fail: Exception | None = None
        self.zmscore_calls = 0

    async def get(self, key: str):
        if self.fail is not None:
            raise self.fail
        return self.store.get(key)

    async def zmscore(self, key: str, members: list[str]):
        self.zmscore_calls += 1
        if self.fail is not None:
            raise self.fail
        z = self.zsets.get(key, {})
        return [z.get(m) for m in members]

    def zadd_gt(self, key: str, mapping: dict[str, int]) -> None:
        z = self.zsets.setdefault(key, {})
        for m, v in mapping.items():
            if m not in z or v > z[m]:
                z[m] = float(v)


class MiniCore:
    """The truth, and both of Core's endpoints."""

    def __init__(self, tenant: uuid.UUID) -> None:
        self.tenant = tenant
        self.pv = 1
        self.gv = 1
        self.roles: dict[uuid.UUID, set[str]] = {}
        self.members: dict[uuid.UUID, dict] = {}   # user -> {"roles": [...], "active": bool}
        self.revoked_sessions: set[str] = set()     # jtis Core refuses
        self.me_calls = 0
        self.map_calls = 0
        self.map_status: int | None = None          # force an error on the role map endpoint
        self.omit_roles: set[uuid.UUID] = set()
        self.tokens: dict[str, tuple[uuid.UUID, str]] = {}

    # writes (each bumps exactly what Core's triggers bump)
    def add_role(self, *codes: str) -> uuid.UUID:
        rid = uuid.uuid4()
        self.roles[rid] = set(codes)
        self.gv += 1
        return rid

    def edit_role(self, rid: uuid.UUID, *codes: str) -> None:
        self.roles[rid] = set(codes)
        self.gv += 1

    def add_member(self, user: uuid.UUID, *roles: uuid.UUID) -> None:
        self.members[user] = {"roles": list(roles), "active": True}
        self.pv += 1

    def set_member_roles(self, user: uuid.UUID, *roles: uuid.UUID) -> None:
        self.members[user]["roles"] = list(roles)
        self.pv += 1

    def deactivate(self, user: uuid.UUID) -> None:
        self.members[user]["active"] = False
        self.pv += 1

    def publish(self, redis: FakeRedis) -> None:
        redis.zadd_gt("role:perms:ver", {str(self.tenant): self.pv, "grants": self.gv})

    def token_for(self, user: uuid.UUID) -> tuple[AuthContext, str]:
        """A token minted NOW: rid = the member's roles, pv = the current tenant pv."""
        jti = str(uuid.uuid4())
        token = f"tok-{jti}"
        self.tokens[token] = (user, jti)
        ctx = AuthContext(
            user_id=user, tenant_id=self.tenant, tenant_slug="t", role="R", archetype="CLINICIAN", facility_ids=None,
            person_id=None, provider_id=None, is_platform_admin=False, jti=jti,
            issued_at=datetime.now(UTC) - timedelta(seconds=5),
            role_ids=tuple(sorted(self.members[user]["roles"], key=str)), roles_version=self.pv,
        )
        return ctx, token

    async def handle(self, request: httpx.Request) -> httpx.Response:
        token = request.headers.get("authorization", "").removeprefix("Bearer ")
        user, jti = self.tokens.get(token, (None, None))
        if request.url.path == perm.PERMISSIONS_PATH:
            self.me_calls += 1
            if user is None or jti in self.revoked_sessions or not self.members[user]["active"]:
                return httpx.Response(401, json={})
            codes: set[str] = set()
            for r in self.members[user]["roles"]:
                codes |= self.roles[r]
            return httpx.Response(200, json={"permissions": sorted(codes)})
        assert request.url.path == perm.ROLE_PERMISSIONS_PATH
        self.map_calls += 1
        if self.map_status is not None:
            return httpx.Response(self.map_status, json={})
        wanted = [uuid.UUID(x) for x in request.url.params["role_ids"].split(",")]
        roles = {str(r): sorted(self.roles[r]) for r in wanted if r in self.roles and r not in self.omit_roles}
        etag = '"' + hashlib.sha256(json.dumps(roles, sort_keys=True).encode()).hexdigest()[:32] + '"'
        headers = {"ETag": etag, "X-Permission-Version": str(self.pv), "X-Grant-Version": str(self.gv)}
        if request.headers.get("if-none-match") == etag:
            return httpx.Response(304, headers=headers)
        return httpx.Response(200, headers=headers, json={
            "tenant_id": str(self.tenant), "roles_version": self.pv, "grant_version": self.gv, "roles": roles,
        })


@pytest.fixture(autouse=True)
def _fresh(monkeypatch):
    monkeypatch.delenv(metrics.ENV_FLAG, raising=False)
    monkeypatch.delenv(perm.ROLE_MAP_ENV, raising=False)
    metrics.reset_metrics()
    yield
    sr._checker = None
    blumax_auth.reset_permissions()
    metrics.reset_metrics()


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def redis() -> FakeRedis:
    r = FakeRedis()
    sr._checker = sr._Checker(r, mode="enforce")  # type: ignore[arg-type]
    return r


@pytest.fixture
def core() -> MiniCore:
    return MiniCore(uuid.uuid4())


def _checker(core: MiniCore, clock: FakeClock, *, role_map: bool = True, **over) -> _Checker:
    kwargs = dict(
        core_url=CORE, ttl_seconds=30.0, timeout_seconds=2.0, max_entries=1000,
        transport=httpx.MockTransport(core.handle), clock=clock,
        breaker_failures=5, breaker_open_seconds=10.0, retry_on_no_answer=False, stale_grace_seconds=0.0,
        role_map=role_map,
    )
    kwargs.update(over)
    return _Checker(**kwargs)


def _setup(core: MiniCore, redis: FakeRedis) -> tuple[uuid.UUID, uuid.UUID]:
    doctor = core.add_role(CODE, OTHER)
    user = uuid.uuid4()
    core.add_member(user, doctor)
    core.publish(redis)
    return doctor, user


# ─── switch off: nothing changes ──────────────────────────────────────────────

async def test_off_by_default_every_check_asks_core_as_before(core, redis, clock):
    _, user = _setup(core, redis)
    checker = _checker(core, clock, role_map=False)
    ctx, token = core.token_for(user)
    assert CODE in (await checker.granted(ctx, token)).codes
    assert core.me_calls == 1 and core.map_calls == 0 and redis.zmscore_calls == 0


def test_configure_reads_the_env_switch(monkeypatch):
    blumax_auth.configure_permissions(core_url=CORE)
    assert perm._checker._role_map is False
    monkeypatch.setenv(perm.ROLE_MAP_ENV, "true")
    blumax_auth.configure_permissions(core_url=CORE)
    assert perm._checker._role_map is True
    blumax_auth.configure_permissions(core_url=CORE, role_map=False)
    assert perm._checker._role_map is False


def test_version_cache_is_capped_at_five_seconds():
    c = _Checker(core_url=CORE, ttl_seconds=30, timeout_seconds=2, max_entries=10, transport=None, clock=FakeClock(),
                 role_map=True, version_cache_seconds=60)
    assert c._version_ttl == MAX_VERSION_CACHE_SECONDS == 5.0


# ─── the hit path ─────────────────────────────────────────────────────────────

async def test_many_callers_of_one_role_cost_one_map_fetch_and_no_me_permissions(core, redis, clock):
    doctor, user = _setup(core, redis)
    others = [uuid.uuid4() for _ in range(20)]
    for u in others:
        core.add_member(u, doctor)
    core.publish(redis)
    checker = _checker(core, clock)
    for u in [user, *others]:
        ctx, token = core.token_for(u)
        for _ in range(5):
            assert (await checker.granted(ctx, token)).codes == frozenset({CODE, OTHER})
    assert core.me_calls == 0
    assert core.map_calls == 1
    assert redis.zmscore_calls == 1                     # one versions read for the tenant within the 5 s window
    assert metrics.snapshot().get("role_map_hit") == 105


async def test_stacked_roles_are_a_union(core, redis, clock):
    a = core.add_role(CODE)
    b = core.add_role(OTHER)
    user = uuid.uuid4()
    core.add_member(user, a, b)
    core.publish(redis)
    checker = _checker(core, clock)
    ctx, token = core.token_for(user)
    assert (await checker.granted(ctx, token)).codes == frozenset({CODE, OTHER})
    assert core.me_calls == 0


async def test_a_missing_code_is_a_403_through_require_permission_too(core, redis, clock):
    reader = core.add_role(OTHER)
    user = uuid.uuid4()
    core.add_member(user, reader)
    core.publish(redis)
    checker = _checker(core, clock)
    ctx, token = core.token_for(user)
    assert CODE not in (await checker.granted(ctx, token)).codes
    perm._checker = checker
    assert await blumax_auth.check_permission(ctx, token, CODE) is False
    assert await blumax_auth.check_permission(ctx, token, OTHER) is True
    assert core.me_calls == 0


async def test_unrelated_grant_edit_is_a_304_not_a_new_map(core, redis, clock):
    doctor, user = _setup(core, redis)
    checker = _checker(core, clock)
    ctx, token = core.token_for(user)
    await checker.granted(ctx, token)
    core.add_role("labs.result.enter")                  # gv bump, our role untouched
    core.publish(redis)
    clock.advance(5.1)
    assert CODE in (await checker.granted(ctx, token)).codes
    assert core.map_calls == 2 and core.me_calls == 0   # asked, got 304, reused


# ─── revocation within the version window ─────────────────────────────────────

async def test_role_edit_revokes_within_the_version_window_for_an_old_token(core, redis, clock):
    doctor, user = _setup(core, redis)
    checker = _checker(core, clock)
    ctx, token = core.token_for(user)                   # minted BEFORE the edit
    assert CODE in (await checker.granted(ctx, token)).codes
    core.edit_role(doctor, OTHER)                       # CODE revoked from the role
    core.publish(redis)
    clock.advance(MAX_VERSION_CACHE_SECONDS)            # the version cache window
    assert CODE not in (await checker.granted(ctx, token)).codes
    assert core.me_calls == 0                           # the token is still trusted for its roles; only the map changed


async def test_membership_role_removal_revokes_within_the_window(core, redis, clock):
    doctor, user = _setup(core, redis)
    viewer = core.add_role("opd.visit.list")
    core.publish(redis)
    checker = _checker(core, clock)
    ctx, token = core.token_for(user)
    assert CODE in (await checker.granted(ctx, token)).codes
    core.set_member_roles(user, viewer)                 # pv bump: the token's rid is now wrong
    core.publish(redis)
    clock.advance(MAX_VERSION_CACHE_SECONDS)
    answer = await checker.granted(ctx, token)          # pv mismatch -> Core's own answer
    assert CODE not in answer.codes and answer.codes == frozenset({"opd.visit.list"})
    assert core.me_calls == 1


async def test_deactivation_revokes_within_the_window(core, redis, clock):
    _, user = _setup(core, redis)
    checker = _checker(core, clock)
    ctx, token = core.token_for(user)
    assert CODE in (await checker.granted(ctx, token)).codes
    core.deactivate(user)
    core.publish(redis)
    clock.advance(MAX_VERSION_CACHE_SECONDS)
    with pytest.raises(InvalidToken):
        await checker.granted(ctx, token)               # Core refuses the deactivated user: 401, as before


async def test_before_the_window_ends_redis_lag_is_caught_by_cores_own_pv(core, redis, clock):
    """Core's DB moved but Redis has not been published yet AND the map must be fetched: Core's answer carries the DB pv, so the
    stale token is not answered from the map."""
    doctor, user = _setup(core, redis)
    checker = _checker(core, clock)
    ctx, token = core.token_for(user)
    viewer = core.add_role("opd.visit.list")            # gv bump (unpublished)
    core.set_member_roles(user, viewer)                 # pv bump (unpublished)
    answer = await checker.granted(ctx, token)          # map empty -> fetch -> Core pv != token pv -> old path
    assert CODE not in answer.codes
    assert core.me_calls == 1


# ─── fallbacks: never grant on doubt ──────────────────────────────────────────

async def test_redis_down_falls_back_to_core(core, redis, clock):
    _, user = _setup(core, redis)
    checker = _checker(core, clock)
    ctx, token = core.token_for(user)
    redis.fail = ConnectionError("down")
    assert CODE in (await checker.granted(ctx, token)).codes
    assert core.me_calls == 1 and core.map_calls == 0
    assert metrics.snapshot().get("role_map_fallback") == 1


async def test_redis_down_after_a_hit_falls_back_once_the_versions_expire(core, redis, clock):
    doctor, user = _setup(core, redis)
    checker = _checker(core, clock)
    ctx, token = core.token_for(user)
    await checker.granted(ctx, token)
    core.deactivate(user)                               # Core can no longer publish (Redis down)
    redis.fail = ConnectionError("down")
    clock.advance(MAX_VERSION_CACHE_SECONDS)
    with pytest.raises(InvalidToken):
        await checker.granted(ctx, token)


async def test_a_revoked_session_falls_back_and_core_refuses_it(core, redis, clock):
    _, user = _setup(core, redis)
    checker = _checker(core, clock)
    ctx, token = core.token_for(user)
    redis.store[f"session_revoked_at:{user}"] = datetime.now(UTC).isoformat()
    core.revoked_sessions.add(ctx.jti)
    with pytest.raises(InvalidToken):
        await checker.granted(ctx, token)
    assert core.map_calls == 0


async def test_logout_after_a_hit_stops_within_the_window(core, redis, clock):
    _, user = _setup(core, redis)
    checker = _checker(core, clock)
    ctx, token = core.token_for(user)
    await checker.granted(ctx, token)
    redis.store[f"session_revoked_at:{user}"] = datetime.now(UTC).isoformat()
    core.revoked_sessions.add(ctx.jti)
    clock.advance(MAX_VERSION_CACHE_SECONDS)
    with pytest.raises(InvalidToken):
        await checker.granted(ctx, token)


async def test_no_session_revocation_configured_means_the_old_path(core, redis, clock):
    _, user = _setup(core, redis)
    sr._checker = None
    checker = _checker(core, clock)
    ctx, token = core.token_for(user)
    await checker.granted(ctx, token)
    assert core.me_calls == 1 and core.map_calls == 0


@pytest.mark.parametrize("drop", ["rid", "pv", "service"])
async def test_missing_claims_or_a_service_token_use_the_old_path(core, redis, clock, drop):
    import dataclasses

    _, user = _setup(core, redis)
    checker = _checker(core, clock)
    ctx, token = core.token_for(user)
    ctx = dataclasses.replace(ctx, **({"role_ids": None} if drop == "rid" else {"roles_version": None} if drop == "pv" else {"is_service": True}))
    await checker.granted(ctx, token)
    assert core.me_calls == 1 and core.map_calls == 0


async def test_unknown_role_falls_back(core, redis, clock):
    doctor, user = _setup(core, redis)
    core.omit_roles.add(doctor)                         # e.g. a role of another tenant
    checker = _checker(core, clock)
    ctx, token = core.token_for(user)
    await checker.granted(ctx, token)
    assert core.me_calls == 1


async def test_role_map_endpoint_failure_falls_back(core, redis, clock):
    _, user = _setup(core, redis)
    core.map_status = 503
    checker = _checker(core, clock)
    ctx, token = core.token_for(user)
    assert CODE in (await checker.granted(ctx, token)).codes
    assert core.me_calls == 1


async def test_missing_versions_in_redis_fall_back(core, redis, clock):
    _, user = _setup(core, redis)
    redis.zsets.clear()                                  # Redis restarted, Core has not re-published yet
    checker = _checker(core, clock)
    ctx, token = core.token_for(user)
    await checker.granted(ctx, token)
    assert core.me_calls == 1 and core.map_calls == 0


async def test_platform_admin_still_passes_without_any_lookup(core, redis, clock):
    import dataclasses

    _, user = _setup(core, redis)
    perm._checker = _checker(core, clock)
    ctx, token = core.token_for(user)
    assert await blumax_auth.check_permission(dataclasses.replace(ctx, is_platform_admin=True), token, "anything") is True
    assert core.me_calls == 0 and core.map_calls == 0 and redis.zmscore_calls == 0


# ─── claims parsing ───────────────────────────────────────────────────────────

async def test_rid_and_pv_are_parsed_from_a_signed_token():
    signer = Signer()
    blumax_auth.reset()
    blumax_auth.configure(jwks_url="http://unused.invalid/jwks.json", issuer=ISSUER, audience=AUDIENCE)
    blumax_auth.jwks_cache().seed(signer.jwks())
    a, b = uuid.uuid4(), uuid.uuid4()
    try:
        ctx = await blumax_auth.verifier().verify(signer.token(rid=[str(b), str(a), str(a)], pv=7))
        assert ctx.role_ids == tuple(sorted({a, b}, key=str)) and ctx.roles_version == 7
        for bad in ({"rid": ["nope"], "pv": 7}, {"rid": [str(a)], "pv": "7"}, {"rid": [str(a)], "pv": True}, {"rid": [], "pv": 1},
                    {"rid": str(a), "pv": 1}, {"pv": 3}, {"rid": [str(a)]}):
            ctx = await blumax_auth.verifier().verify(signer.token(**bad))
            assert ctx.role_ids is None and ctx.roles_version is None, bad
    finally:
        blumax_auth.reset()


def test_forbidden_and_invalid_token_are_unchanged_types():
    assert issubclass(Forbidden, blumax_auth.AuthError) and issubclass(InvalidToken, blumax_auth.AuthError)
