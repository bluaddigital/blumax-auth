"""Authenticated identity-management operations -- the production-ready
replacement for scripts/create_dev_user.py's dev-only bootstrap.

Deliberately thin, per ARCHITECTURE.md's own boundary: this module knows
"who exists and whether they're active," nothing about tenant/role/
facility/application-specific state. A caller that needs those creates its
own local record (e.g. Labs' LabUser) separately and links it to the id
this module returns.
"""
from __future__ import annotations

import secrets
import uuid

import structlog
from redis.asyncio import Redis
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.security import hash_password
from app.core.session_revocation import revoke_user_sessions
from app.models.user import User

logger = structlog.get_logger(__name__)


class IdentityError(Exception):
    pass


class DuplicateIdentifierError(IdentityError):
    pass


class IdentityNotFoundError(IdentityError):
    pass


def _generate_temp_password() -> str:
    # URL-safe, long enough to be a strong one-time credential; never
    # logged, returned exactly once in the create-identity response.
    return secrets.token_urlsafe(18)


async def create_identity(
    db: AsyncSession, *, identifier: str, password: str | None,
    username: str | None = None, created_user_id: uuid.UUID | None = None,
) -> tuple[User, str | None]:
    existing = await db.execute(select(User).where(User.identifier == identifier))
    if existing.scalar_one_or_none() is not None:
        raise DuplicateIdentifierError(f"identifier already exists: {identifier!r}")
    if username is not None:
        existing_username = await db.execute(select(User).where(User.username == username))
        if existing_username.scalar_one_or_none() is not None:
            raise DuplicateIdentifierError(f"username already exists: {username!r}")

    temp_password = None
    if password is None:
        temp_password = _generate_temp_password()
        raw_password = temp_password
    else:
        raw_password = password

    user = User(
        id=uuid.uuid4(), identifier=identifier, username=username,
        hashed_password=hash_password(raw_password), is_active=True,
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    logger.info("identity.created", user_id=str(user.id), created_by=str(created_user_id) if created_user_id else None)
    return user, temp_password


async def create_identity_with_id(
    db: AsyncSession, *, user_id: uuid.UUID, identifier: str, hashed_password: str, is_active: bool,
    username: str | None = None,
) -> User:
    """Preserves an EXPLICITLY SUPPLIED id -- the one operation
    create_identity() above deliberately does not support, since a normal
    admin-created identity should always get a fresh, Blumax-Auth-
    generated id. This exists only for the identity-migration path (see
    scripts/migrate_core_user.py), where preserving an existing Core
    `users.id` as the new `sub` is the entire point (see docs/
    PHASE5_BLUMAX_AUTH_CAPABILITY_COMPLETION.md's identity-migration
    section). `hashed_password` is accepted pre-hashed (a byte-copy of an
    existing bcrypt hash), never re-hashed here."""
    existing = await db.execute(select(User).where(User.identifier == identifier))
    if existing.scalar_one_or_none() is not None:
        raise DuplicateIdentifierError(f"identifier already exists: {identifier!r}")
    if username is not None:
        existing_username = await db.execute(select(User).where(User.username == username))
        if existing_username.scalar_one_or_none() is not None:
            raise DuplicateIdentifierError(f"username already exists: {username!r}")

    user = User(
        id=user_id, identifier=identifier, username=username,
        hashed_password=hashed_password, is_active=is_active,
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    logger.info("identity.migrated", user_id=str(user.id))
    return user


async def get_identity(db: AsyncSession, user_id: uuid.UUID) -> User:
    user = await db.get(User, user_id)
    if user is None:
        raise IdentityNotFoundError(str(user_id))
    return user


async def set_active(db: AsyncSession, redis: Redis, *, user_id: uuid.UUID, is_active: bool) -> User:
    user = await get_identity(db, user_id)
    user.is_active = is_active
    await db.commit()
    if not is_active:
        # A deactivated identity must not keep a still-unexpired access
        # token working until natural expiry -- same reasoning as a
        # password change revoking existing sessions.
        await revoke_user_sessions(redis, str(user_id))
    logger.info("identity.active_changed", user_id=str(user_id), is_active=is_active)
    return user


async def admin_set_password(db: AsyncSession, redis: Redis, *, user_id: uuid.UUID, new_password: str) -> None:
    if len(new_password) < settings.PASSWORD_MIN_LENGTH:
        raise IdentityError(f"password must be at least {settings.PASSWORD_MIN_LENGTH} characters")
    user = await get_identity(db, user_id)
    user.hashed_password = hash_password(new_password)
    await db.commit()
    await revoke_user_sessions(redis, str(user_id))
    logger.info("identity.password_admin_set", user_id=str(user_id))
