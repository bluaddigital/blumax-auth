from __future__ import annotations

from pydantic import BaseModel


class LoginRequest(BaseModel):
    identifier: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class RefreshRequest(BaseModel):
    refresh_token: str


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
