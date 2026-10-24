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
