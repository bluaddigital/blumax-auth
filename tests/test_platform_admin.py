"""blumax_auth.require_platform_admin / PlatformAdminAuth.

Why this exists separately from require_role()/require_archetype(): both of
those depend on require_tenant, which is right for a route that acts on ONE
tenant's own data. It is wrong for a route that manages a platform-wide
resource instead (the case that motivated this: OPD's specialty_master, the
single global department/specialty list every organization reads) — a
superadmin's own token often carries no tenant at all, and require_tenant
would refuse them with TenantContextMissing before is_platform_admin was ever
checked. This dependency checks only the `adm` claim, with no tenant binding.
"""
from __future__ import annotations

import uuid

import httpx
import pytest
from fastapi import FastAPI
from test_verification import AUDIENCE, ISSUER, Signer

import blumax_auth


@pytest.fixture
def signer() -> Signer:
    return Signer()


@pytest.fixture
def app(signer: Signer):
    blumax_auth.reset()
    blumax_auth.configure(jwks_url="http://unused.invalid/jwks.json", issuer=ISSUER, audience=AUDIENCE)
    blumax_auth.jwks_cache().seed(signer.jwks())

    application = FastAPI()
    blumax_auth.install_error_handler(application)

    @application.get("/admin-only")
    async def admin_only(ctx: blumax_auth.PlatformAdminAuth) -> dict:
        return {"user_id": str(ctx.user_id), "tenant_id": str(ctx.tenant_id) if ctx.tenant_id else None}

    yield application
    blumax_auth.reset()


@pytest.fixture
async def client(app: FastAPI):
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as c:
        yield c


def _headers(signer: Signer, **claims) -> dict[str, str]:
    return {"Authorization": f"Bearer {signer.token(**claims)}"}


class TestAdditive:
    def test_importable_from_the_package_root(self):
        from blumax_auth import PlatformAdminAuth, require_platform_admin  # noqa: F401

    def test_every_pre_existing_export_is_still_there(self):
        before = {
            "Auth", "AuthContext", "AuthError", "Forbidden", "InvalidToken", "JwksCache",
            "MissingCredentials", "TenantAuth", "TenantContextMissing", "TenantMismatch",
            "TokenVerifier", "configure", "install_error_handler", "jwks_cache",
            "require_auth", "require_archetype", "require_role", "require_tenant", "reset",
        }
        assert before <= set(blumax_auth.__all__)


class TestNoTenantRequired:
    """The defect this exists to fix, stated as a test: a platform admin
    token with NO tenant claim must pass, where TenantAuth would refuse it."""

    async def test_a_platform_admin_with_no_tenant_at_all_passes(self, client, signer):
        resp = await client.get("/admin-only", headers=_headers(signer, adm=True, tid=None))
        assert resp.status_code == 200, resp.text
        assert resp.json()["tenant_id"] is None

    async def test_a_platform_admin_bound_to_a_tenant_still_passes(self, client, signer):
        tid = str(uuid.uuid4())
        resp = await client.get("/admin-only", headers=_headers(signer, adm=True, tid=tid))
        assert resp.status_code == 200, resp.text
        assert resp.json()["tenant_id"] == tid


class TestRefusesNonAdmins:
    async def test_an_ordinary_tenant_caller_is_refused(self, client, signer):
        resp = await client.get("/admin-only", headers=_headers(signer, adm=False))
        assert resp.status_code == 403, resp.text
        assert resp.json()["error"]["code"] == "FORBIDDEN"

    async def test_a_tenant_admin_archetype_is_still_refused(self, client, signer):
        """adm=False is the actual gate — arc/rol being an admin-sounding
        name inside one hospital must not be mistaken for platform authority."""
        resp = await client.get(
            "/admin-only", headers=_headers(signer, adm=False, arc="TENANT_ADMIN", rol="TENANT_ADMIN")
        )
        assert resp.status_code == 403, resp.text

    async def test_no_token_at_all_is_refused(self, client):
        resp = await client.get("/admin-only")
        assert resp.status_code == 401, resp.text

    async def test_the_response_never_mentions_a_tenant_problem(self, client, signer):
        """A non-admin refusal must read as an authorization failure, not the
        old TenantContextMissing this dependency was built to avoid."""
        resp = await client.get("/admin-only", headers=_headers(signer, adm=False, tid=None))
        assert resp.status_code == 403
        assert "TENANT_CONTEXT" not in resp.text
