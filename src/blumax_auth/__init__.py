"""Verify BluMax Core-issued JWTs.

Verification only. This package holds no private key and cannot mint a token —
that asymmetry is the reason Core signs with RS256 rather than a shared secret.

Exists as one package rather than a file copied per service because it already
was copied per service: OPD, IPD and Appointments each shipped a byte-identical
41-line security.py, none of them wired up. Three copies of dead code is what
drift looks like before it starts.
"""
from blumax_auth.context import AuthContext
from blumax_auth.errors import (
    AuthError,
    Forbidden,
    InvalidToken,
    MissingCredentials,
    TenantContextMissing,
    TenantMismatch,
)
from blumax_auth.fastapi import (
    Auth,
    TenantAuth,
    configure,
    install_error_handler,
    jwks_cache,
    require_auth,
    require_archetype,
    require_role,
    require_tenant,
    reset,
)
from blumax_auth.jwks import JwksCache
from blumax_auth.verify import TokenVerifier

__all__ = [
    "Auth",
    "AuthContext",
    "AuthError",
    "Forbidden",
    "InvalidToken",
    "JwksCache",
    "MissingCredentials",
    "TenantAuth",
    "TenantContextMissing",
    "TenantMismatch",
    "TokenVerifier",
    "configure",
    "install_error_handler",
    "jwks_cache",
    "require_auth",
    "require_archetype",
    "require_role",
    "require_tenant",
    "reset",
]
