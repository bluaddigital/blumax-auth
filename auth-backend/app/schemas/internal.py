from __future__ import annotations

import uuid

from pydantic import BaseModel


class UserSyncRequest(BaseModel):
    """Mirrors Core's own `users` row shape exactly (see
    scripts/migrate_core_user.py's --source-json format) -- same fields,
    same optionality. `identifier`/`username` are optional here because
    Core's user.password_changed event carries only user_id + the new
    hashed_password (see EventTypes.USER_PASSWORD_CHANGED's own docstring
    in blumax-backend); user.created always sends every field."""

    user_id: uuid.UUID
    identifier: str | None = None
    username: str | None = None
    hashed_password: str
    is_active: bool | None = None


class MembershipSyncRequest(BaseModel):
    """Mirrors Core's TENANT_MEMBER_ROLE_ASSIGNED event payload exactly
    (user_id, membership_id, role_id, role_name, role_archetype) plus
    tenant_id/tenant_slug the relay adds from the envelope itself. facility_ids
    defaults to an empty list, never omitted and never null -- see
    app/models/tenant_membership.py's own docstring for why this table never
    stores Core's "None means unrestricted" reading."""

    user_id: uuid.UUID
    tenant_id: uuid.UUID
    tenant_slug: str | None = None
    role_name: str
    role_archetype: str = "VIEWER"
    facility_ids: list[uuid.UUID] = []


class MembershipRevokedRequest(BaseModel):
    user_id: uuid.UUID
    tenant_id: uuid.UUID
