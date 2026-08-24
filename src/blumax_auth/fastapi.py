"""FastAPI wiring — the three dependencies a service actually puts on its routes.

Typical setup in a service's app factory:

    from blumax_auth import configure, install_error_handler

    configure(
        jwks_url=f"{settings.CORE_API_URL}/.well-known/jwks.json",
        issuer=settings.JWT_ISSUER,
        audience=settings.JWT_AUDIENCE,
    )
    install_error_handler(app)             # renders the shared error envelope

and then on routes:

    async def get_worklist(ctx: TenantAuth) -> ...:
        ...ctx.tenant_id...
"""
from __future__ import annotations

import uuid
from collections.abc import Callable
from typing import Annotated

from fastapi import Depends, Header, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from blumax_auth.context import AuthContext
from blumax_auth.errors import (
    AuthError,
    Forbidden,
    MissingCredentials,
    TenantContextMissing,
    TenantMismatch,
)
from blumax_auth.jwks import JwksCache
from blumax_auth.verify import TokenVerifier

_bearer = HTTPBearer(auto_error=False)

_verifier: TokenVerifier | None = None
_jwks: JwksCache | None = None


def configure(
    *,
    jwks_url: str,
    issuer: str,
    audience: str,
    ttl_seconds: float = 3600.0,
    leeway_seconds: int = 30,
) -> None:
    """Point this service at Core's key set. Call once, at app startup."""
    global _verifier, _jwks
    _jwks = JwksCache(jwks_url, ttl_seconds=ttl_seconds)
    _verifier = TokenVerifier(
        _jwks, issuer=issuer, audience=audience, leeway_seconds=leeway_seconds
    )


def jwks_cache() -> JwksCache:
    """The live cache — tests seed it to avoid a real Core."""
    if _jwks is None:
        raise RuntimeError("blumax_auth.configure() has not been called")
    return _jwks


def reset() -> None:
    """Drop configuration. Tests only."""
    global _verifier, _jwks
    _verifier = None
    _jwks = None


# ─── Dependencies ─────────────────────────────────────────────────────────────

async def require_auth(
    request: Request,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)] = None,
) -> AuthContext:
    """Any authenticated caller. Does not require a tenant binding."""
    if _verifier is None:
        raise RuntimeError("blumax_auth.configure() has not been called")
    if credentials is None:
        raise MissingCredentials()

    ctx = await _verifier.verify(credentials.credentials)
    # Stash so handlers and logging can reach it without re-verifying.
    request.state.auth = ctx
    return ctx


async def require_tenant(
    ctx: Annotated[AuthContext, Depends(require_auth)],
    x_tenant_id: Annotated[uuid.UUID | None, Header(alias="X-Tenant-ID")] = None,
) -> AuthContext:
    """An authenticated caller bound to a tenant.

    The tenant comes from the signed `tid` claim. X-Tenant-ID is still read,
    but only to be checked: if it disagrees with the claim the request is
    refused. It can never select the tenant, which is the difference between a
    provable isolation boundary and a header anyone can retype.

    Accepting a matching header rather than ignoring it keeps existing callers
    working through the migration, while the disagreement case is already
    closed.
    """
    if ctx.tenant_id is None:
        raise TenantContextMissing()
    if x_tenant_id is not None and x_tenant_id != ctx.tenant_id:
        raise TenantMismatch()
    return ctx


def require_role(*roles: str) -> Callable[..., object]:
    """Restrict a route to specific roles or archetypes.

    Matches EITHER the role name or the archetype, and that is the point.
    Every existing call site names a system role — require_role("CLINICIAN") —
    and those roles carry the identically-named archetype, so nothing about
    their behaviour changes. What changes is what happens when a hospital
    creates "Senior Registrar" with the CLINICIAN archetype: the holder now
    passes, where a name-only check would have refused them a module their
    hospital pays for, in a service that has no way to learn the new name.

    Prefer require_archetype() in new code, which says that outright.

    Platform admins pass regardless — their authority is cross-tenant by
    definition, and making every route list PLATFORM_ADMIN would guarantee that
    somebody eventually forgets.
    """
    allowed = frozenset(roles)

    async def _check(
        ctx: Annotated[AuthContext, Depends(require_tenant)],
    ) -> AuthContext:
        if ctx.is_platform_admin:
            return ctx
        if ctx.role not in allowed and ctx.archetype not in allowed:
            raise Forbidden(f"Requires one of: {', '.join(sorted(allowed))}")
        return ctx

    return _check


def require_archetype(*archetypes: str) -> Callable[..., object]:
    """Restrict a route to callers holding one of these archetypes.

    The check downstream services should be making. There are only ever three
    values (TENANT_ADMIN, CLINICIAN, VIEWER), they are Core's stable contract,
    and no amount of role-naming inside a hospital can invent a fourth.
    """
    allowed = frozenset(archetypes)

    async def _check(
        ctx: Annotated[AuthContext, Depends(require_tenant)],
    ) -> AuthContext:
        if ctx.is_platform_admin:
            return ctx
        if ctx.archetype not in allowed:
            raise Forbidden(f"Requires one of: {', '.join(sorted(allowed))}")
        return ctx

    return _check


# ─── Error handling ───────────────────────────────────────────────────────────

def install_error_handler(app: object, renderer: Callable[[AuthError], object] | None = None) -> None:
    """Render AuthError in the platform's standard error envelope.

    Core, OPD, IPD and Appointments all return
    ``{"error": {"code", "message", "details"}}``. Emitting that here means an
    auth failure looks like every other failure, instead of FastAPI's
    ``{"detail": ...}`` — which the services' own contract tests assert against.

    A handler must RETURN a response; re-raising as the service's own error type
    does not work, because Starlette does not re-dispatch exceptions raised
    inside a handler. Pass `renderer` if a service ever diverges from the
    shared envelope.
    """
    from fastapi.responses import JSONResponse  # noqa: PLC0415

    async def _handler(request: Request, exc: Exception):  # noqa: ANN202, ARG001
        assert isinstance(exc, AuthError)
        if renderer is not None:
            return renderer(exc)
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "error": {
                    "code": exc.error_code,
                    "message": exc.message,
                    "details": {},
                }
            },
        )

    app.add_exception_handler(AuthError, _handler)  # type: ignore[attr-defined]


# ─── Route-signature aliases ──────────────────────────────────────────────────

Auth = Annotated[AuthContext, Depends(require_auth)]
TenantAuth = Annotated[AuthContext, Depends(require_tenant)]
