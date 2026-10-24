"""Keeps this service's own `users` table in sync with Core's, driven by
Core's blumax_auth_user_sync_relay.py (user.created / user.password_changed).
See app/schemas/internal.py's own docstring for the two event shapes this
single upsert handles.
"""
from __future__ import annotations

import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.user import User


class UserSyncConflictError(Exception):
    """The identifier belongs to a DIFFERENT existing user_id -- never
    auto-resolved, same posture as migrate_core_user.py's own ConflictRow
    handling. The relay's own _TERMINAL_STATUS_CODES treats this as
    terminal (409), not retried."""


def _normalize_identifier(identifier: str) -> str:
    """Same policy as scripts/migrate_core_user.py's normalize_identifier
    -- trim, lowercase, nothing more aggressive. Kept in sync deliberately;
    duplicated rather than imported from a script module."""
    return identifier.strip().lower()


async def sync_user_from_core(
    db: AsyncSession,
    *,
    user_id: uuid.UUID,
    identifier: str | None,
    username: str | None,
    hashed_password: str,
    is_active: bool | None,
) -> None:
    """Upsert by user_id -- Core's own id is preserved exactly (see
    migrate_core_user.py's module docstring for why this matters: every
    consumer link column that keys on core_user_id depends on it).

    A user.password_changed event sends only user_id + hashed_password
    (identifier/username/is_active are None) -- those fields are left
    untouched on an existing row, and a password-changed event for a
    user_id this table has never seen is a no-op (there is nothing to
    create from a bare password alone; the next user.created-shaped sync,
    if one ever arrives, creates it properly)."""
    existing = await db.get(User, user_id)

    if existing is None:
        if identifier is None:
            return
        db.add(User(
            id=user_id, identifier=_normalize_identifier(identifier),
            username=username, hashed_password=hashed_password,
            is_active=is_active if is_active is not None else True,
        ))
        await db.commit()
        return

    if identifier is not None:
        normalized = _normalize_identifier(identifier)
        if normalized != existing.identifier:
            conflict = (
                await db.execute(select(User).where(User.identifier == normalized))
            ).scalar_one_or_none()
            if conflict is not None and conflict.id != user_id:
                raise UserSyncConflictError(
                    f"identifier {normalized!r} already belongs to a different user_id"
                )
            existing.identifier = normalized
        existing.username = username
    existing.hashed_password = hashed_password
    if is_active is not None:
        existing.is_active = is_active
    await db.commit()
