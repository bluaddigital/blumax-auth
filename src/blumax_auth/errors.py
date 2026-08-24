"""Errors this package raises.

Deliberately not fastapi.HTTPException. Every BluMax service renders errors as
``{"error": {"code", "message", "details"}}`` through its own handler, and
HTTPException would emit ``{"detail": ...}`` instead — breaking the one response
shape clients can rely on. Each service maps AuthError onto its own error base
in three lines; see install_error_handler().
"""
from __future__ import annotations


class AuthError(Exception):
    """Authentication or authorization failure, with the status a service should return."""

    status_code: int = 401
    error_code: str = "AUTHENTICATION_FAILED"
    message: str = "Authentication required"

    def __init__(self, message: str | None = None) -> None:
        super().__init__(message or self.message)
        if message is not None:
            self.message = message


class MissingCredentials(AuthError):
    status_code = 401
    error_code = "AUTHENTICATION_FAILED"
    message = "Authorization header required"


class InvalidToken(AuthError):
    status_code = 401
    error_code = "AUTHENTICATION_FAILED"
    message = "Invalid or expired token"


class TenantContextMissing(AuthError):
    """Authenticated, but the token is not bound to a tenant.

    400 rather than 401 or 403: the caller proved who they are, and the request
    is refused because the session carries no tenant — a different problem from
    bad credentials, and one the client fixes by choosing a tenant rather than
    signing in again.
    """

    status_code = 400
    error_code = "TENANT_CONTEXT_MISSING"
    message = "This session is not bound to a tenant"


class TenantMismatch(AuthError):
    """X-Tenant-ID disagrees with the tenant the token is signed for."""

    status_code = 403
    error_code = "TENANT_ACCESS_DENIED"
    message = "X-Tenant-ID does not match the tenant this token is bound to"


class Forbidden(AuthError):
    status_code = 403
    error_code = "FORBIDDEN"
    message = "You do not have permission to perform this action"
