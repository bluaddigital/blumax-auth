from __future__ import annotations

import uuid

from pydantic import BaseModel


class LoginRequest(BaseModel):
    identifier: str
    password: str
    # Required only when the account holds more than one active tenant
    # membership (see auth_service.TenantSelectionRequiredError) -- same
    # shape as Core's own LoginCommand.tenant_id.
    tenant_id: uuid.UUID | None = None


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class RefreshRequest(BaseModel):
    refresh_token: str
    # The tenant binding is preserved across a refresh -- see Core's own
    # AuthService.refresh docstring for why this is supplied by the
    # caller rather than stored server-side: the client remembers which
    # tenant it's bound to and resends it on every refresh, same as login.
    tenant_id: uuid.UUID | None = None


class LogoutRequest(BaseModel):
    refresh_token: str
    all_devices: bool = False


class MeResponse(BaseModel):
    sub: str
    iss: str
    aud: str
    type: str
    # Added Phase 4I-1 (Superadmin frontend integration): the identifier
    # this identity originally logged in with (email or username,
    # whatever Core's own login field held at migration time -- see
    # scripts/migrate_core_user.py). Purely for a caller to display
    # something human-readable; never used by this service's own
    # verification/authorization, which reads only `sub`. None only in
    # the already-impossible case of `sub` resolving to no User row at
    # all (a verified token implies the row exists, since there is
    # nothing else `sub` could have come from).
    identifier: str | None = None
    # 2026-10-25: surfaced straight from the token's own claims (never
    # re-resolved here) when present -- same abbreviated names as the JWT
    # itself (tid/tsl/rol/arc/fac), so a caller already parsing Core's
    # /auth/me shape needs no new field names.
    tid: str | None = None
    tsl: str | None = None
    rol: str | None = None
    arc: str | None = None
    fac: list[str] | None = None
