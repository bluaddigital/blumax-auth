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
from sqlalchemy import or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.security import hash_password
from app.core.session_revocation import revoke_user_sessions
from app.models.tenant_namespace import TenantNamespace, normalize_slug
from app.models.user import User, normalize_identifier, normalize_username

logger = structlog.get_logger(__name__)


class IdentityError(Exception):
    pass


class DuplicateIdentifierError(IdentityError):
    pass


class IdentityNotFoundError(IdentityError):
    pass


class TenantSlugConflictError(IdentityError):
    pass


class TenantScopedIdentityDisabledError(IdentityError):
    pass


def _generate_temp_password() -> str:
    # URL-safe, long enough to be a strong one-time credential; never
    # logged, returned exactly once in the create-identity response.
    return secrets.token_urlsafe(18)


async def create_identity(
    db: AsyncSession, *, identifier: str, password: str | None,
    username: str | None = None, created_user_id: uuid.UUID | None = None,
    tenant_id: uuid.UUID | None = None, tenant_slug: str | None = None,
) -> tuple[User, str | None]:
    if tenant_id is not None:
        return await _create_tenant_identity(
            db, tenant_id=tenant_id, tenant_slug=tenant_slug, identifier=identifier,
            password=password, username=username, created_user_id=created_user_id,
        )
    if tenant_slug is not None:
        raise IdentityError("tenant_slug requires tenant_id")

    existing = await db.execute(select(User).where(User.identifier == identifier, User.tenant_id.is_(None)))
    if existing.scalar_one_or_none() is not None:
        raise DuplicateIdentifierError(f"identifier already exists: {identifier!r}")
    if username is not None:
        existing_username = await db.execute(
            select(User).where(User.username == username, User.tenant_id.is_(None))
        )
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
        username_normalized=normalize_username(username),
        hashed_password=hash_password(raw_password), is_active=True,
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    logger.info("identity.created", user_id=str(user.id), created_by=str(created_user_id) if created_user_id else None)
    return user, temp_password


async def _register_tenant_slug(db: AsyncSession, *, tenant_id: uuid.UUID, tenant_slug: str) -> None:
    """Records the tenant's login slug (hospital code). Idempotent for the
    same pair; refuses to re-point a slug to another tenant or to rename a
    tenant's existing slug implicitly."""
    slug = normalize_slug(tenant_slug)
    if not slug:
        raise IdentityError("tenant_slug must not be blank")
    by_tenant = await db.get(TenantNamespace, tenant_id)
    if by_tenant is not None:
        if by_tenant.slug != slug:
            raise TenantSlugConflictError(
                f"tenant already registered with a different slug: {by_tenant.slug!r}"
            )
        return
    by_slug = (
        await db.execute(select(TenantNamespace).where(TenantNamespace.slug == slug))
    ).scalar_one_or_none()
    if by_slug is not None:
        raise TenantSlugConflictError(f"tenant slug already belongs to another tenant: {slug!r}")
    db.add(TenantNamespace(tenant_id=tenant_id, slug=slug))


async def _create_tenant_identity(
    db: AsyncSession, *, tenant_id: uuid.UUID, tenant_slug: str | None, identifier: str,
    password: str | None, username: str | None, created_user_id: uuid.UUID | None,
) -> tuple[User, str | None]:
    """A tenant-scoped account (owner decision 2026-11-28): unique only
    within `tenant_id`. The same identifier/username in another tenant is a
    separate account and is never looked at, let alone linked. Within the
    tenant, a login name may not collide with EITHER login column of
    another account (identifier "ravi" vs another account's username
    "ravi" would make login ambiguous)."""
    if not settings.tenant_scoped_identity_enabled:
        raise TenantScopedIdentityDisabledError(
            "tenant-scoped identities are disabled (TENANT_SCOPED_IDENTITY_MODE=off)"
        )
    norm_identifier = normalize_identifier(identifier)
    if not norm_identifier:
        raise IdentityError("identifier must not be blank")
    norm_username = normalize_username(username)
    names = {norm_identifier} | ({norm_username} if norm_username else set())
    clash = (
        await db.execute(
            select(User.id).where(
                User.tenant_id == tenant_id,
                or_(User.identifier.in_(names), User.username_normalized.in_(names)),
            ).limit(1)
        )
    ).scalar_one_or_none()
    if clash is not None:
        raise DuplicateIdentifierError("identifier or username already exists in this tenant")

    if tenant_slug is not None:
        await _register_tenant_slug(db, tenant_id=tenant_id, tenant_slug=tenant_slug)

    temp_password = None
    if password is None:
        temp_password = _generate_temp_password()
        raw_password = temp_password
    else:
        raw_password = password

    user = User(
        id=uuid.uuid4(), tenant_id=tenant_id, identifier=norm_identifier,
        username=username.strip() if username and username.strip() else None,
        username_normalized=norm_username,
        hashed_password=hash_password(raw_password), is_active=True,
    )
    db.add(user)
    try:
        await db.commit()
    except IntegrityError as exc:
        # A concurrent create won the race on one of the partial unique
        # indexes -- same answer as the pre-check above.
        await db.rollback()
        raise DuplicateIdentifierError("identifier, username or tenant slug already exists") from exc
    await db.refresh(user)
    logger.info(
        "identity.created", user_id=str(user.id), tenant_id=str(tenant_id),
        created_by=str(created_user_id) if created_user_id else None,
    )
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
    existing = await db.execute(select(User).where(User.identifier == identifier, User.tenant_id.is_(None)))
    if existing.scalar_one_or_none() is not None:
        raise DuplicateIdentifierError(f"identifier already exists: {identifier!r}")
    if username is not None:
        existing_username = await db.execute(
            select(User).where(User.username == username, User.tenant_id.is_(None))
        )
        if existing_username.scalar_one_or_none() is not None:
            raise DuplicateIdentifierError(f"username already exists: {username!r}")

    user = User(
        id=user_id, identifier=identifier, username=username,
        username_normalized=normalize_username(username),
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
