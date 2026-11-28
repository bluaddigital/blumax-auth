from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel


class CreateIdentityRequest(BaseModel):
    identifier: str
    password: str | None = None  # omitted -> a random temp password is generated and returned once
    username: str | None = None  # optional second login identifier, mirroring Core's own email/username duality
    # Tenant-scoped staff identity (2026-11-28, requires
    # TENANT_SCOPED_IDENTITY_MODE=on): the account is created inside this
    # tenant's namespace only. Omitted -> a global (legacy) identity, as before.
    tenant_id: uuid.UUID | None = None
    # Optional hospital code / tenant slug to register for this tenant so
    # login can name the tenant by slug. Only with tenant_id.
    tenant_slug: str | None = None


class CreateIdentityResponse(BaseModel):
    id: str
    identifier: str
    username: str | None = None
    is_active: bool
    temporary_password: str | None = None  # only present when `password` was omitted
    tenant_id: str | None = None


class IdentityResponse(BaseModel):
    id: str
    identifier: str
    username: str | None = None
    is_active: bool
    created_at: datetime
    tenant_id: str | None = None


class SetPasswordRequest(BaseModel):
    new_password: str
