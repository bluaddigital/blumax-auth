"""Standalone Blumax Auth service -- Phase 1 (see MIGRATION.md): built and
tested in parallel, not yet consumed by any production application. Core
remains the production authentication authority until a later migration
phase explicitly repoints a consumer at this service.
"""
from __future__ import annotations

import structlog
from fastapi import FastAPI

from app.api.identity_routes import identity_router
from app.api.password_routes import password_router
from app.api.routes import health_router, jwks_router, router
from app.api.service_routes import service_router
from app.api.sso_routes import sso_router

structlog.configure(
    processors=[
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.add_log_level,
        # Never log secrets: passwords, hashes, private keys, or raw
        # token values are never passed as log fields anywhere in this
        # service -- only user_id/jti/identifier/reason, confirmed by
        # inspection of every logger.* call site in app/services and
        # app/core.
        structlog.processors.JSONRenderer(),
    ]
)


def create_app() -> FastAPI:
    app = FastAPI(
        title="Blumax Auth",
        description="Centralized identity/authentication. Verification-only "
        "consumers should keep using the blumax_auth package; this service "
        "is the issuer.",
    )
    app.include_router(router)
    app.include_router(jwks_router)
    app.include_router(health_router)
    app.include_router(sso_router)
    app.include_router(service_router)
    app.include_router(password_router)
    app.include_router(identity_router)
    return app


app = create_app()
