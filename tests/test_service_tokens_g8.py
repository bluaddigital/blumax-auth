# ruff: noqa: F811 -- the fixtures are imported from test_local_permissions and requested by name
"""0.6.4 (G8): local evaluation of SCOPED service tokens, and AuthContext.actor from a delegated token's `act` claim.

A scoped service token (Core SERVICE_TOKEN_SCOPES=enforce) is `type: "service"`, `ver: 2`, with `perm` = the role's
codes INTERSECT the account's scopes: it is answered from the token like a staff v2 token. An unscoped service token
(no `perm`) keeps asking Core (fallback service_token), exactly as in 0.6.2.
"""
from __future__ import annotations

import uuid

import pytest
from test_local_permissions import (  # noqa: F401 -- fixtures
    CATALOGUE,
    HELD,
    PERMS,
    FakeClock,
    FakeCore,
    FakeRedis,
    _clean,
    bearer,
    client,
    clock,
    configure,
    core,
    mint,
    redis,
    settle,
    signer,
)
from test_verification import AUDIENCE, ISSUER, Signer

import blumax_auth
from blumax_auth import Actor, InvalidToken, JwksCache, TokenVerifier, metrics


class TestScopedServiceTokenLocal:
    @pytest.fixture(autouse=True)
    def _local(self, core, clock, redis):
        configure(core, clock, redis, local_mode="local")

    async def test_scoped_service_token_is_answered_from_the_token(self, client, signer, core):
        token = mint(signer, type="service", codes=(HELD,))
        core.grant(token, HELD)
        assert (await client.get("/held", headers=bearer(token))).status_code == 200  # preload starts; Core asked
        await settle()
        assert (await client.get("/held", headers=bearer(token))).status_code == 200
        assert (await client.get("/not-held", headers=bearer(token))).status_code == 403
        assert core.calls(CATALOGUE) == 1
        snap = metrics.local_snapshot()
        assert snap.get("local_allow", 0) >= 1 and snap.get("local_deny") == 1

    async def test_scoped_service_token_narrower_than_core_is_denied_locally(self, client, signer, core):
        """The cap wins: Core's role answer may be broader, the token's perm is what the service account may use."""
        token = mint(signer, type="service", codes=())
        core.grant(token, HELD)
        await client.get("/held", headers=bearer(token))
        await settle()
        assert (await client.get("/held", headers=bearer(token))).status_code == 403

    async def test_unscoped_service_token_still_falls_back(self, client, signer, core):
        token = mint(signer, type="service", perm=None)
        core.grant(token, HELD)
        assert (await client.get("/held", headers=bearer(token))).status_code == 200
        assert core.calls(PERMS) == 1 and core.calls(CATALOGUE) == 0
        assert metrics.local_snapshot() == {"fallback:service_token": 1}

    async def test_v1_service_token_with_a_stray_perm_falls_back(self, client, signer, core):
        token = mint(signer, v2=False, type="service", perm={"cv": 3, "b": ""})
        core.grant(token, HELD)
        assert (await client.get("/held", headers=bearer(token))).status_code == 200
        assert metrics.local_snapshot() == {"fallback:service_token": 1}

    async def test_stale_authz_ver_asks_core(self, client, signer, core):
        token = mint(signer, type="service", codes=(HELD,), authz_ver=1)
        core.grant(token)
        assert (await client.get("/held", headers=bearer(token))).status_code == 403
        assert metrics.local_snapshot() == {"fallback:authz_ver_stale": 1}


class TestOffIsUnchanged:
    async def test_off_asks_core_for_a_scoped_service_token(self, client, signer, core, clock, redis):
        configure(core, clock, redis, local_mode="off")
        token = mint(signer, type="service", codes=())
        core.grant(token, HELD)
        assert (await client.get("/held", headers=bearer(token))).status_code == 200
        assert core.calls(PERMS) == 1 and core.calls(CATALOGUE) == 0


def _verifier(signer: Signer) -> TokenVerifier:
    cache = JwksCache("http://unused.invalid/jwks.json")
    cache.seed(signer.jwks())
    return TokenVerifier(cache, issuer=ISSUER, audience=AUDIENCE)


class TestActor:
    async def test_delegated_token_exposes_the_actor(self, signer):
        sa = uuid.uuid4()
        ctx = await _verifier(signer).verify(signer.token(act={"sub": str(sa), "svc": "platform-labs-documents"}))
        assert ctx.actor == Actor(service_account_id=sa, service_name="platform-labs-documents")
        assert ctx.is_delegated and not ctx.is_service

    async def test_actor_without_svc(self, signer):
        sa = uuid.uuid4()
        ctx = await _verifier(signer).verify(signer.token(act={"sub": str(sa)}))
        assert ctx.actor == Actor(service_account_id=sa, service_name=None)

    async def test_no_act_is_none(self, signer):
        ctx = await _verifier(signer).verify(signer.token())
        assert ctx.actor is None and not ctx.is_delegated

    @pytest.mark.parametrize("act", ["platform-x", {"sub": "not-a-uuid"}, {"svc": "x"}, []])
    async def test_malformed_act_is_refused(self, signer, act):
        with pytest.raises(InvalidToken):
            await _verifier(signer).verify(signer.token(act=act))

    async def test_service_token_cannot_carry_an_actor(self, signer):
        with pytest.raises(InvalidToken):
            await _verifier(signer).verify(signer.token(type="service", act={"sub": str(uuid.uuid4())}))

