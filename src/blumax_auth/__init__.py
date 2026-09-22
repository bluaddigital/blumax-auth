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
    PlatformAdminAuth,
    TenantAuth,
    configure,
    install_error_handler,
    jwks_cache,
    require_archetype,
    require_auth,
    require_platform_admin,
    require_role,
    require_tenant,
    reset,
)
from blumax_auth.jwks import JwksCache
from blumax_auth.permissions import (
    PermissionCheckUnavailable,
    aclose_permissions,
    configure_permissions,
    require_permission,
    reset_permissions,
)
from blumax_auth.session_revocation import (
    aclose_session_revocation,
    check_session_revocation,
    configure_session_revocation,
    reset_session_revocation,
)
from blumax_auth.verify import TokenVerifier

__all__ = [
    "Auth",
    "PlatformAdminAuth",
    "AuthContext",
    "AuthError",
    "Forbidden",
    "InvalidToken",
    "JwksCache",
    "MissingCredentials",
    "PermissionCheckUnavailable",
    "TenantAuth",
    "TenantContextMissing",
    "TenantMismatch",
    "TokenVerifier",
    "aclose_permissions",
    "aclose_session_revocation",
    "check_session_revocation",
    "configure",
    "configure_permissions",
    "configure_session_revocation",
    "install_error_handler",
    "jwks_cache",
    "require_auth",
    "require_archetype",
    "require_permission",
    "require_platform_admin",
    "require_role",
    "require_tenant",
    "reset",
    "reset_permissions",
    "reset_session_revocation",
]
