"""blumax_auth.require_permission — the opt-in permission check against Core.

Core is replaced by an httpx.MockTransport so the package is tested standalone, and
time by a fake clock so cache expiry is deterministic. Each class below maps onto
one line of the Step 5 acceptance gate.
"""
from __future__ import annotations

import asyncio
import dataclasses
import inspect
import logging
import uuid
from datetime import UTC, datetime, timedelta
from typing import Annotated

import httpx
import pytest
from fastapi import Depends, FastAPI
from test_verification import AUDIENCE, ISSUER, Signer

import blumax_auth
from blumax_auth import AuthContext

CODE = "opd.consultation.create"
CORE = "http://core.test"

# Route-signature aliases, built once: the dependency object is a module-level
# singleton rather than a call in an argument default.
Consult = Annotated[AuthContext, Depends(blumax_auth.require_permission(CODE))]
ConsultWarn = Annotated[AuthContext, Depends(blumax_auth.require_permission(CODE, mode="warn"))]
ClinicianOnly = Annotated[AuthContext, Depends(blumax_auth.require_archetype("CLINICIAN"))]


# ─── Fakes ────────────────────────────────────────────────────────────────────

class FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


class FakeCore:
    """Stands in for Core's GET /api/v1/me/permissions.

    Answers per bearer token, the way Core answers per caller. Records every
    request so tests can assert what was — and was not — sent.
    """

    def __init__(self) -> None:
        self.requests: list[httpx.Request] = []
        self.by_token: dict[str, tuple[int, object]] = {}
        self.delay = 0.0
        self.fail: Exception | None = None

    @property
    def calls(self) -> int:
        return len(self.requests)

    def grant(self, token: str, *codes: str) -> None:
        self.by_token[token] = (200, {
            "role_id": str(uuid.uuid4()), "role_name": "Some Role",
            "archetype": "CLINICIAN", "is_platform_admin": False,
            "permissions": sorted(codes),
        })

    def respond(self, token: str, status: int, body: object = None) -> None:
        self.by_token[token] = (status, body if body is not None else {})

    async def handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if self.delay:
            await asyncio.sleep(self.delay)
        if self.fail is not None:
            raise self.fail
        token = request.headers.get("authorization", "").removeprefix("Bearer ")
        status, body = self.by_token.get(token, (401, {"error": {"code": "AUTHENTICATION_FAILED"}}))
        if isinstance(body, str):
            return httpx.Response(status, text=body)
        return httpx.Response(status, json=body)


# ─── Fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture
def signer() -> Signer:
    return Signer()


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def core() -> FakeCore:
    return FakeCore()


def _configure(core: FakeCore, clock: FakeClock, **over) -> None:
    kwargs = dict(
        core_url=CORE, ttl_seconds=30.0, timeout_seconds=2.0,
        transport=httpx.MockTransport(core.handle), clock=clock,
    )
    kwargs.update(over)
    blumax_auth.configure_permissions(**kwargs)


@pytest.fixture
def app(signer: Signer, core: FakeCore, clock: FakeClock):
    blumax_auth.reset()
    blumax_auth.reset_permissions()
    blumax_auth.configure(jwks_url="http://unused.invalid/jwks.json", issuer=ISSUER, audience=AUDIENCE)
    blumax_auth.jwks_cache().seed(signer.jwks())
    _configure(core, clock)

    application = FastAPI()
    blumax_auth.install_error_handler(application)

    @application.get("/consult")
    async def consult(ctx: Consult) -> dict:
        return {"user_id": str(ctx.user_id), "tenant_id": str(ctx.tenant_id)}

    @application.get("/consult-warn")
    async def consult_warn(ctx: ConsultWarn) -> dict:
        return {"user_id": str(ctx.user_id)}

    @application.get("/plain")
    async def plain(ctx: blumax_auth.TenantAuth) -> dict:
        return {"tenant_id": str(ctx.tenant_id)}

    @application.post("/visits/{visit_id}/cancel")
    async def cancel(visit_id: uuid.UUID, ctx: ConsultWarn) -> dict:
        return {"visit_id": str(visit_id)}

    yield application
    blumax_auth.reset_permissions()
    blumax_auth.reset()


@pytest.fixture
async def client(app: FastAPI):
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as c:
        yield c


def _caller(signer: Signer, core: FakeCore, *codes: str, **claims) -> tuple[dict[str, str], str]:
    """A signed token, registered with the fake Core as holding `codes`."""
    token = signer.token(**claims)
    core.grant(token, *codes)
    return {"Authorization": f"Bearer {token}"}, token


# ─── 1. Importable, additive ──────────────────────────────────────────────────

class TestAdditive:
    def test_new_api_is_importable_from_the_package_root(self):
        from blumax_auth import (  # noqa: F401
            PermissionCheckUnavailable,
            aclose_permissions,
            configure_permissions,
            require_permission,
            reset_permissions,
        )

    def test_every_pre_existing_export_is_still_there(self):
        # The public surface before this change (0.1.0). Removing or renaming any
        # of these would break a consuming service.
        before = {
            "Auth", "AuthContext", "AuthError", "Forbidden", "InvalidToken", "JwksCache",
            "MissingCredentials", "TenantAuth", "TenantContextMissing", "TenantMismatch",
            "TokenVerifier", "configure", "install_error_handler", "jwks_cache",
            "require_auth", "require_archetype", "require_role", "require_tenant", "reset",
        }
        assert before <= set(blumax_auth.__all__)
        assert all(hasattr(blumax_auth, name) for name in before)

    def test_existing_dependency_modules_do_not_reference_the_new_helper(self):
        # No existing route can start using it by accident: nothing that was
        # already there imports it.
        import blumax_auth.context as context
        import blumax_auth.errors as errors
        import blumax_auth.fastapi as fastapi_mod
        import blumax_auth.jwks as jwks
        import blumax_auth.verify as verify

        for module in (context, errors, fastapi_mod, jwks, verify):
            source = inspect.getsource(module)
            assert "require_permission" not in source, module.__name__
            assert "blumax_auth.permissions" not in source, module.__name__

    async def test_existing_dependencies_work_with_permissions_never_configured(self, signer):
        # A service that does not opt in is unaffected, even though the package
        # now ships the helper.
        blumax_auth.reset()
        blumax_auth.reset_permissions()
        blumax_auth.configure(jwks_url="http://unused.invalid/j", issuer=ISSUER, audience=AUDIENCE)
        blumax_auth.jwks_cache().seed(signer.jwks())
        application = FastAPI()
        blumax_auth.install_error_handler(application)

        @application.get("/scoped")
        async def scoped(ctx: blumax_auth.TenantAuth) -> dict:
            return {"tenant_id": str(ctx.tenant_id)}

        @application.get("/clin")
        async def clin(ctx: ClinicianOnly) -> dict:
            return {"a": ctx.archetype}

        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=application), base_url="http://t") as c:
            h = {"Authorization": f"Bearer {signer.token()}"}
            assert (await c.get("/scoped", headers=h)).status_code == 200
            assert (await c.get("/clin", headers=h)).status_code == 200
            assert (await c.get("/scoped")).status_code == 401
        blumax_auth.reset()


# ─── 2/3. Valid → allowed, missing → denied ───────────────────────────────────

class TestDecision:
    async def test_a_caller_holding_the_code_is_allowed(self, client, signer, core):
        h, _ = _caller(signer, core, CODE, "view_patient")
        r = await client.get("/consult", headers=h)
        assert r.status_code == 200, r.text
        assert core.calls == 1

    async def test_a_caller_lacking_the_code_is_denied(self, client, signer, core):
        h, _ = _caller(signer, core, "opd.consultation.view", "view_patient")
        r = await client.get("/consult", headers=h)
        assert r.status_code == 403
        body = r.json()["error"]
        assert body["code"] == "FORBIDDEN"
        assert CODE in body["message"]

    async def test_a_similar_code_is_not_the_code(self, client, signer, core):
        # Exact match only — no prefix, suffix or wildcard reading.
        for near in ("opd.consultation.create.x", "opd.consultation", "opd.consultation.*",
                     "OPD.CONSULTATION.CREATE", " opd.consultation.create"):
            h, _ = _caller(signer, core, near)
            assert (await client.get("/consult", headers=h)).status_code == 403, near

    async def test_an_empty_grant_list_is_a_denial(self, client, signer, core):
        h, _ = _caller(signer, core)
        assert (await client.get("/consult", headers=h)).status_code == 403

    async def test_the_handler_receives_the_verified_context_unchanged(self, client, signer, core):
        uid, tid = uuid.uuid4(), uuid.uuid4()
        h, _ = _caller(signer, core, CODE, sub=str(uid), tid=str(tid))
        body = (await client.get("/consult", headers=h)).json()
        assert body == {"user_id": str(uid), "tenant_id": str(tid)}

    async def test_a_platform_admin_passes_without_asking_core(self, client, signer, core):
        token = signer.token(adm=True)
        r = await client.get("/consult", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200
        assert core.calls == 0


# ─── 4. Invalid / expired caller token ────────────────────────────────────────

class TestAuthenticationFirst:
    async def test_no_credentials_is_401_and_core_is_not_asked(self, client, core):
        r = await client.get("/consult")
        assert r.status_code == 401
        assert core.calls == 0

    async def test_an_expired_token_is_401_and_core_is_not_asked(self, client, signer, core):
        past = datetime.now(UTC) - timedelta(hours=1)
        token = signer.token(exp=past, iat=past - timedelta(minutes=10))
        core.grant(token, CODE)     # Core would say yes; it must never be consulted
        r = await client.get("/consult", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 401
        assert core.calls == 0

    async def test_a_token_signed_by_someone_else_is_401(self, client, core):
        forged = Signer(kid="test-key-1").token()      # same kid, different private key
        core.grant(forged, CODE)
        r = await client.get("/consult", headers={"Authorization": f"Bearer {forged}"})
        assert r.status_code == 401
        assert core.calls == 0

    async def test_a_tenantless_token_is_400_and_core_is_not_asked(self, client, signer, core):
        token = signer.token(tid=None)
        core.grant(token, CODE)
        r = await client.get("/consult", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 400
        assert core.calls == 0

    async def test_a_token_core_itself_rejects_is_refused(self, client, signer, core):
        # Verified locally, refused by Core (revoked session, key rotation not yet
        # seen here). Must be a refusal, never an implicit allow.
        token = signer.token()
        core.respond(token, 401)
        r = await client.get("/consult", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 401

    async def test_core_saying_403_or_404_is_a_403(self, client, signer, core):
        for status in (403, 404):
            token = signer.token()
            core.respond(token, status, {"error": {"code": "TENANT_ACCESS_DENIED"}})
            r = await client.get("/consult", headers={"Authorization": f"Bearer {token}"})
            assert r.status_code == 403, status


# ─── 5. Core unavailable: deterministic, never an accidental allow ────────────

class TestCoreUnavailable:
    async def _refused(self, client, signer, core):
        h, _ = _caller(signer, core, CODE)
        r = await client.get("/consult", headers=h)
        assert r.status_code == 503, r.text
        assert r.json()["error"]["code"] == "PERMISSION_CHECK_UNAVAILABLE"
        return h

    async def test_connection_refused(self, client, signer, core):
        core.fail = httpx.ConnectError("refused")
        await self._refused(client, signer, core)

    async def test_timeout(self, client, signer, core):
        core.fail = httpx.ReadTimeout("slow")
        await self._refused(client, signer, core)

    async def test_server_errors(self, client, signer, core):
        for status in (500, 502, 503, 429):
            token = signer.token()
            core.respond(token, status)
            r = await client.get("/consult", headers={"Authorization": f"Bearer {token}"})
            assert r.status_code == 503, status

    async def test_a_malformed_answer_is_not_an_allow(self, client, signer, core):
        bad_bodies = [
            "not json at all",
            {"unexpected": "shape"},
            {"permissions": "opd.consultation.create"},         # a string, not a list
            {"permissions": [CODE, 7]},                          # not all strings
            {"permissions": None},
            [CODE],                                              # a bare list
        ]
        for body in bad_bodies:
            token = signer.token()
            core.respond(token, 200, body)
            r = await client.get("/consult", headers={"Authorization": f"Bearer {token}"})
            assert r.status_code == 503, body

    async def test_a_failure_is_not_cached_and_recovery_is_immediate(self, client, signer, core):
        h, _ = _caller(signer, core, CODE)
        core.fail = httpx.ConnectError("down")
        assert (await client.get("/consult", headers=h)).status_code == 503
        assert (await client.get("/consult", headers=h)).status_code == 503
        assert core.calls == 2                                   # each one asked again
        core.fail = None                                         # Core comes back
        assert (await client.get("/consult", headers=h)).status_code == 200

    async def test_a_failure_does_not_serve_a_previously_cached_allow(self, client, signer, core, clock):
        # Fail closed even for a caller who was allowed a moment ago: after the TTL
        # a dead Core must not extend a grant that may since have been revoked.
        h, _ = _caller(signer, core, CODE)
        assert (await client.get("/consult", headers=h)).status_code == 200
        clock.advance(31)
        core.fail = httpx.ConnectError("down")
        assert (await client.get("/consult", headers=h)).status_code == 503

    async def test_an_outage_costs_one_attempt_for_concurrent_requests(self, client, signer, core):
        h, _ = _caller(signer, core, CODE)
        core.fail = httpx.ConnectError("down")
        core.delay = 0.05
        results = await asyncio.gather(*[client.get("/consult", headers=h) for _ in range(20)])
        assert {r.status_code for r in results} == {503}
        assert core.calls == 1


# ─── 6. Tenant context cannot be substituted by the caller ────────────────────

class TestTenantIsTheSignedTenant:
    async def test_core_is_asked_about_the_tenant_in_the_token(self, client, signer, core):
        tid = uuid.uuid4()
        h, token = _caller(signer, core, CODE, tid=str(tid))
        assert (await client.get("/consult", headers=h)).status_code == 200
        sent = core.requests[0]
        assert sent.headers["x-tenant-id"] == str(tid)
        assert sent.headers["authorization"] == f"Bearer {token}"
        assert sent.url.path == "/api/v1/me/permissions"

    async def test_a_different_x_tenant_id_is_refused_and_core_is_not_asked(self, client, signer, core):
        h, _ = _caller(signer, core, CODE, tid=str(uuid.uuid4()))
        r = await client.get("/consult", headers={**h, "X-Tenant-ID": str(uuid.uuid4())})
        assert r.status_code == 403
        assert r.json()["error"]["code"] == "TENANT_ACCESS_DENIED"
        assert core.calls == 0

    async def test_a_matching_header_is_accepted_and_changes_nothing(self, client, signer, core):
        tid = uuid.uuid4()
        h, _ = _caller(signer, core, CODE, tid=str(tid))
        r = await client.get("/consult", headers={**h, "X-Tenant-ID": str(tid)})
        assert r.status_code == 200
        assert core.requests[0].headers["x-tenant-id"] == str(tid)

    async def test_only_the_callers_own_credentials_and_tenant_reach_core(self, client, signer, core):
        h, token = _caller(signer, core, CODE)
        await client.get("/consult", headers={**h, "X-Forwarded-For": "1.2.3.4", "Cookie": "a=b"})
        sent = core.requests[0]
        assert sent.headers["authorization"] == f"Bearer {token}"
        assert "cookie" not in sent.headers and "x-forwarded-for" not in sent.headers


# ─── 7. Cache isolation ───────────────────────────────────────────────────────

class TestCacheIsolation:
    async def test_a_second_request_from_the_same_caller_is_served_from_cache(self, client, signer, core):
        h, _ = _caller(signer, core, CODE)
        for _i in range(5):
            assert (await client.get("/consult", headers=h)).status_code == 200
        assert core.calls == 1

    async def test_two_users_in_one_tenant_never_share_an_answer(self, client, signer, core):
        tid = str(uuid.uuid4())
        allowed_h, _ = _caller(signer, core, CODE, tid=tid, sub=str(uuid.uuid4()))
        denied_h, _ = _caller(signer, core, "view_patient", tid=tid, sub=str(uuid.uuid4()))

        assert (await client.get("/consult", headers=allowed_h)).status_code == 200   # populates cache
        assert (await client.get("/consult", headers=denied_h)).status_code == 403    # must not inherit it
        assert (await client.get("/consult", headers=allowed_h)).status_code == 200
        assert core.calls == 2

    async def test_a_denial_is_not_replayed_to_someone_who_is_allowed(self, client, signer, core):
        tid = str(uuid.uuid4())
        denied_h, _ = _caller(signer, core, "view_patient", tid=tid, sub=str(uuid.uuid4()))
        allowed_h, _ = _caller(signer, core, CODE, tid=tid, sub=str(uuid.uuid4()))
        assert (await client.get("/consult", headers=denied_h)).status_code == 403
        assert (await client.get("/consult", headers=allowed_h)).status_code == 200

    async def test_the_same_user_in_two_tenants_gets_two_entries(self, client, signer, core):
        uid = str(uuid.uuid4())
        a_h, _ = _caller(signer, core, CODE, sub=uid, tid=str(uuid.uuid4()))
        b_h, _ = _caller(signer, core, "view_patient", sub=uid, tid=str(uuid.uuid4()))
        assert (await client.get("/consult", headers=a_h)).status_code == 200
        assert (await client.get("/consult", headers=b_h)).status_code == 403
        assert core.calls == 2

    async def test_two_tokens_of_one_user_do_not_share_an_entry(self, client, signer, core):
        uid, tid = str(uuid.uuid4()), str(uuid.uuid4())
        first, _ = _caller(signer, core, CODE, sub=uid, tid=tid)
        second, _ = _caller(signer, core, CODE, sub=uid, tid=tid)
        await client.get("/consult", headers=first)
        await client.get("/consult", headers=second)
        assert core.calls == 2

    async def test_the_cache_key_names_tenant_user_and_token_not_just_the_code(self, signer, core, clock):
        # Direct look at the key: it must never collapse to (tenant, permission).
        _configure(core, clock)
        checker = blumax_auth.permissions._checker
        tid, uid = uuid.uuid4(), uuid.uuid4()
        ctx = AuthContext(
            user_id=uid, tenant_id=tid, tenant_slug="t", role="R", archetype="CLINICIAN",
            facility_ids=None, person_id=None, provider_id=None, is_platform_admin=False, jti="j",
        )
        token = signer.token(sub=str(uid), tid=str(tid))
        core.grant(token, CODE)
        await checker.granted(ctx, token)
        (key,) = checker._cache.keys()
        assert key[0] == tid and key[1] == uid
        assert len(key) == 3 and key[2] != token          # a digest, never the raw token
        assert CODE not in key

    async def test_the_raw_token_is_never_stored(self, signer, core, clock):
        _configure(core, clock)
        checker = blumax_auth.permissions._checker
        ctx = AuthContext(
            user_id=uuid.uuid4(), tenant_id=uuid.uuid4(), tenant_slug="t", role="R",
            archetype="CLINICIAN", facility_ids=None, person_id=None, provider_id=None,
            is_platform_admin=False, jti="j",
        )
        token = signer.token()
        core.grant(token, CODE)
        await checker.granted(ctx, token)
        assert token not in repr(checker._cache)


# ─── 8. Changes take effect after expiry ──────────────────────────────────────

class TestExpiry:
    async def test_a_revocation_takes_effect_after_the_ttl_not_before(self, client, signer, core, clock):
        h, token = _caller(signer, core, CODE)
        assert (await client.get("/consult", headers=h)).status_code == 200

        core.grant(token, "view_patient")                   # an operator revokes it
        clock.advance(29)
        assert (await client.get("/consult", headers=h)).status_code == 200   # within the TTL: cached
        clock.advance(2)
        assert (await client.get("/consult", headers=h)).status_code == 403   # after: asks Core again

    async def test_a_new_grant_takes_effect_after_the_ttl(self, client, signer, core, clock):
        h, token = _caller(signer, core, "view_patient")
        assert (await client.get("/consult", headers=h)).status_code == 403
        core.grant(token, "view_patient", CODE)
        clock.advance(31)
        assert (await client.get("/consult", headers=h)).status_code == 200

    async def test_a_zero_ttl_disables_the_cache(self, signer, core, clock):
        _configure(core, clock, ttl_seconds=0)
        checker = blumax_auth.permissions._checker
        ctx = AuthContext(
            user_id=uuid.uuid4(), tenant_id=uuid.uuid4(), tenant_slug="t", role="R",
            archetype="CLINICIAN", facility_ids=None, person_id=None, provider_id=None,
            is_platform_admin=False, jti="j",
        )
        token = signer.token()
        core.grant(token, CODE)
        await checker.granted(ctx, token)
        await checker.granted(ctx, token)
        assert core.calls == 2

    async def test_the_cache_is_bounded_and_drops_the_oldest(self, signer, core, clock):
        _configure(core, clock, max_entries=2)
        checker = blumax_auth.permissions._checker

        def ctx() -> AuthContext:
            return AuthContext(
                user_id=uuid.uuid4(), tenant_id=uuid.uuid4(), tenant_slug="t", role="R",
                archetype="CLINICIAN", facility_ids=None, person_id=None, provider_id=None,
                is_platform_admin=False, jti="j",
            )

        callers = []
        for _i in range(3):
            c, t = ctx(), signer.token()
            core.grant(t, CODE)
            callers.append((c, t))
            await checker.granted(c, t)
        assert len(checker._cache) == 2
        before = core.calls
        await checker.granted(*callers[0])                 # evicted: asks Core again
        assert core.calls == before + 1

    async def test_expired_entries_are_purged_as_new_ones_arrive(self, signer, core, clock):
        _configure(core, clock)
        checker = blumax_auth.permissions._checker

        def ctx() -> AuthContext:
            return AuthContext(
                user_id=uuid.uuid4(), tenant_id=uuid.uuid4(), tenant_slug="t", role="R",
                archetype="CLINICIAN", facility_ids=None, person_id=None, provider_id=None,
                is_platform_admin=False, jti="j",
            )

        for _i in range(4):
            c, t = ctx(), signer.token()
            core.grant(t, CODE)
            await checker.granted(c, t)
        clock.advance(31)
        c, t = ctx(), signer.token()
        core.grant(t, CODE)
        await checker.granted(c, t)
        assert len(checker._cache) == 1


# ─── Concurrency ──────────────────────────────────────────────────────────────

class TestConcurrency:
    async def test_concurrent_misses_share_one_call_to_core(self, client, signer, core):
        h, _ = _caller(signer, core, CODE)
        core.delay = 0.05
        results = await asyncio.gather(*[client.get("/consult", headers=h) for _ in range(20)])
        assert {r.status_code for r in results} == {200}
        assert core.calls == 1

    async def test_a_cancelled_request_does_not_cancel_the_shared_fetch(self, signer, core, clock):
        _configure(core, clock)
        checker = blumax_auth.permissions._checker
        ctx = AuthContext(
            user_id=uuid.uuid4(), tenant_id=uuid.uuid4(), tenant_slug="t", role="R",
            archetype="CLINICIAN", facility_ids=None, person_id=None, provider_id=None,
            is_platform_admin=False, jti="j",
        )
        token = signer.token()
        core.grant(token, CODE)
        core.delay = 0.05

        first = asyncio.ensure_future(checker.granted(ctx, token))
        second = asyncio.ensure_future(checker.granted(ctx, token))
        await asyncio.sleep(0.01)
        first.cancel()                                       # the client hung up
        assert (await second).codes == frozenset({CODE})
        assert core.calls == 1


# ─── Warn mode ────────────────────────────────────────────────────────────────

LOGGER = "blumax_auth.permissions"
FIELDS = {
    "decision", "mode", "permission", "route", "method", "tenant_id", "user_id",
    "role", "archetype", "is_service", "cached",
}


# Attributes every LogRecord has (plus what caplog's formatter adds): anything else on a
# record came from `extra`.
_STANDARD_RECORD_ATTRS = set(vars(logging.makeLogRecord({}))) | {"message", "asctime"}


def _events(caplog) -> list[logging.LogRecord]:
    return [r for r in caplog.records if r.name == LOGGER and r.getMessage() == "permission_check"]


class TestWarnMode:
    async def test_a_would_be_denial_is_logged_with_every_field_and_not_refused(
        self, client, signer, core, caplog,
    ):
        tid, uid = uuid.uuid4(), uuid.uuid4()
        h, _ = _caller(signer, core, "view_patient", tid=str(tid), sub=str(uid), rol="Nurse")
        with caplog.at_level(logging.INFO, logger=LOGGER):
            r = await client.get("/consult-warn", headers=h)
        assert r.status_code == 200
        (rec,) = _events(caplog)
        assert rec.levelno == logging.WARNING
        assert set(vars(rec)) >= FIELDS
        assert rec.decision == "would_deny" and rec.reason == "missing_permission"
        assert rec.mode == "warn" and rec.permission == CODE
        assert rec.tenant_id == str(tid) and rec.user_id == str(uid)
        assert rec.role == "Nurse" and rec.archetype == "CLINICIAN" and rec.is_service is False
        assert rec.method == "GET" and rec.route == "/consult-warn"
        assert rec.cached is False and isinstance(rec.core_latency_ms, float)

    async def test_an_allowed_caller_is_logged_at_info(self, client, signer, core, caplog):
        h, _ = _caller(signer, core, CODE)
        with caplog.at_level(logging.INFO, logger=LOGGER):
            assert (await client.get("/consult-warn", headers=h)).status_code == 200
        (rec,) = _events(caplog)
        assert rec.levelno == logging.INFO
        assert rec.decision == "allow" and not hasattr(rec, "reason")

    async def test_cached_and_latency_describe_how_the_answer_was_obtained(
        self, client, signer, core, caplog,
    ):
        h, _ = _caller(signer, core, CODE)
        with caplog.at_level(logging.INFO, logger=LOGGER):
            await client.get("/consult-warn", headers=h)
            await client.get("/consult-warn", headers=h)
        first, second = _events(caplog)
        assert first.cached is False and first.core_latency_ms >= 0
        assert second.cached is True and not hasattr(second, "core_latency_ms")
        assert core.calls == 1

    async def test_a_failure_to_check_is_logged_with_a_reason_and_not_refused(
        self, client, signer, core, caplog,
    ):
        cases = [
            (dict(fail=httpx.ConnectError("down")), "core_unavailable", None),
            (dict(status=500), "core_unavailable", 500),
            (dict(status=401), "core_rejected_token", 401),
            (dict(status=403), "core_forbidden", 403),
            (dict(status=200, body={"permissions": "nope"}), "core_unavailable", 200),
        ]
        for spec, reason, status in cases:
            core.fail = spec.get("fail")
            token = signer.token()
            if "status" in spec:
                core.respond(token, spec["status"], spec.get("body"))
            caplog.clear()
            with caplog.at_level(logging.INFO, logger=LOGGER):
                r = await client.get("/consult-warn", headers={"Authorization": f"Bearer {token}"})
            assert r.status_code == 200, spec
            (rec,) = _events(caplog)
            assert rec.decision == "check_failed" and rec.reason == reason, spec
            assert getattr(rec, "core_status", None) == status, spec
            assert rec.levelno == logging.WARNING
            core.fail = None

    async def test_a_platform_admin_is_logged_as_allowed_without_asking_core(
        self, client, signer, core, caplog,
    ):
        token = signer.token(adm=True)
        with caplog.at_level(logging.INFO, logger=LOGGER):
            r = await client.get("/consult-warn", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200
        (rec,) = _events(caplog)
        assert rec.decision == "allow" and rec.reason == "platform_admin"
        assert core.calls == 0

    async def test_the_log_never_carries_a_token_or_a_permission_list(
        self, client, signer, core, caplog,
    ):
        h, token = _caller(signer, core, "view_patient", "billing.invoice.view", "secret.marker.code")
        with caplog.at_level(logging.DEBUG, logger=LOGGER):
            await client.get("/consult-warn", headers=h)               # would_deny
            await client.get("/consult-warn", headers=h)               # cached would_deny
        records = [r for r in caplog.records if r.name == LOGGER]
        assert records
        for rec in records:
            dumped = repr(vars(rec)) + rec.getMessage()
            assert token not in dumped and token.split(".")[1] not in dumped
            # none of the codes Core returned appear — only the one this route needs
            assert "secret.marker.code" not in dumped and "billing.invoice.view" not in dumped
            # An allow-list, not a deny-list: the only extra fields an event may carry are
            # the documented ones, and every one is a plain scalar.
            extras = {k: v for k, v in vars(rec).items() if k not in _STANDARD_RECORD_ATTRS}
            assert set(extras) <= FIELDS | {"reason", "core_latency_ms", "core_status"}, set(extras)
            assert all(v is None or isinstance(v, (str, int, float, bool)) for v in extras.values())

    async def test_the_route_is_the_template_never_the_concrete_path(
        self, client, signer, core, caplog,
    ):
        h, _ = _caller(signer, core, "view_patient")
        visit = uuid.uuid4()
        with caplog.at_level(logging.INFO, logger=LOGGER):
            r = await client.post(f"/visits/{visit}/cancel", headers=h)
        assert r.status_code == 200
        (rec,) = _events(caplog)
        assert rec.route == "/visits/{visit_id}/cancel" and rec.method == "POST"
        assert str(visit) not in repr(vars(rec))

    def test_with_no_matched_route_the_concrete_path_is_not_substituted(self, caplog):
        from starlette.requests import Request

        import blumax_auth.permissions as permissions

        request = Request({"type": "http", "method": "GET", "path": "/patients/123-456", "headers": []})
        ctx = AuthContext(
            user_id=uuid.uuid4(), tenant_id=uuid.uuid4(), tenant_slug="t", role="R",
            archetype="CLINICIAN", facility_ids=None, person_id=None, provider_id=None,
            is_platform_admin=False, jti="j",
        )
        with caplog.at_level(logging.INFO, logger=LOGGER):
            permissions._emit(request, ctx, CODE, decision="allow", cached=False)
        (rec,) = _events(caplog)
        assert rec.route == "<unmatched>"
        assert "123-456" not in repr(vars(rec))

    async def test_enforce_mode_logs_nothing_even_when_it_allows_and_denies(
        self, client, signer, core, caplog,
    ):
        yes, _ = _caller(signer, core, CODE)
        no, _ = _caller(signer, core, "view_patient")
        with caplog.at_level(logging.DEBUG, logger=LOGGER):
            assert (await client.get("/consult", headers=yes)).status_code == 200
            assert (await client.get("/consult", headers=no)).status_code == 403
        assert not _events(caplog)

    async def test_authentication_is_never_relaxed_by_the_mode(self, client, core):
        assert (await client.get("/consult-warn")).status_code == 401
        assert core.calls == 0

    async def test_a_tenant_mismatch_is_never_relaxed_by_the_mode(self, client, signer, core):
        h, _ = _caller(signer, core, CODE, tid=str(uuid.uuid4()))
        r = await client.get("/consult-warn", headers={**h, "X-Tenant-ID": str(uuid.uuid4())})
        assert r.status_code == 403

    async def test_an_unconfigured_service_logs_instead_of_failing_in_warn_mode(
        self, client, signer, caplog,
    ):
        blumax_auth.reset_permissions()
        token = signer.token()
        with caplog.at_level(logging.INFO, logger=LOGGER):
            r = await client.get("/consult-warn", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200
        (rec,) = _events(caplog)
        assert rec.decision == "check_failed" and rec.reason == "not_configured"


# ─── Configuration and misuse ─────────────────────────────────────────────────

class TestConfiguration:
    async def test_enforce_mode_without_configuration_fails_loudly(self, client, signer):
        blumax_auth.reset_permissions()
        token = signer.token()
        with pytest.raises(RuntimeError, match="configure_permissions"):
            await client.get("/consult", headers={"Authorization": f"Bearer {token}"})

    def test_bad_configuration_is_refused_at_startup(self):
        for bad in (
            dict(core_url=""), dict(core_url="  "), dict(core_url=CORE, ttl_seconds=-1),
            dict(core_url=CORE, timeout_seconds=0), dict(core_url=CORE, max_entries=0),
        ):
            with pytest.raises(ValueError):
                blumax_auth.configure_permissions(**bad)

    def test_a_route_takes_exactly_one_well_formed_code(self):
        for bad in ("", " ", "opd consultation create", "a\tb", None, 7):
            with pytest.raises(ValueError):
                blumax_auth.require_permission(bad)        # type: ignore[arg-type]
        with pytest.raises(ValueError):
            blumax_auth.require_permission(CODE, mode="audit")   # type: ignore[arg-type]
        with pytest.raises(TypeError):
            blumax_auth.require_permission(CODE, "opd.other.view")   # type: ignore[call-arg]

    async def test_close_is_safe_to_call_whether_or_not_it_was_used(self, core, clock):
        await blumax_auth.aclose_permissions()          # unconfigured: no error
        _configure(core, clock)
        await blumax_auth.aclose_permissions()          # configured, never used: no error


# ─── 10/11. Nothing about permissions enters a token or the context ───────────

class TestNoPermissionsInTokens:
    def test_auth_context_has_no_permission_field(self):
        names = {f.name for f in dataclasses.fields(AuthContext)}
        assert not any("perm" in n or "grant" in n or "scope" in n for n in names), names

    def test_the_package_cannot_mint_a_token(self):
        import blumax_auth.permissions as permissions

        source = inspect.getsource(permissions)
        assert "jwt.encode" not in source and "jose" not in source

    async def test_the_verified_token_claims_are_what_the_handler_sees(self, client, signer, core):
        # The helper returns the AuthContext verification built, carrying no extra
        # attribute the permission answer could have been smuggled into.
        h, _ = _caller(signer, core, CODE)
        r = await client.get("/consult", headers=h)
        assert r.status_code == 200
        assert set(r.json()) == {"user_id", "tenant_id"}
