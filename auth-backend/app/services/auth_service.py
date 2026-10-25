"""Login / refresh / logout. Mirrors Core's own AuthService shape
(refresh-token reuse detection revokes the whole family; logout revokes
server-side state, not just client-side discard) because that mechanism
was already sound in the prior audit -- only the fail-open session-
revocation gap was flagged for change (see session_revocation.py), and
the timing-safe password check (see security.py).
"""
from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import structlog
from redis.asyncio import Redis
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import (
    InvalidToken,
    create_access_token,
    create_refresh_token,
    decode_token,
    verify_password_constant_time,
)
from app.core.session_revocation import is_session_revoked, revoke_user_sessions
from app.models.refresh_token import RefreshToken
from app.models.tenant_membership import TenantMembership
from app.models.user import User

logger = structlog.get_logger(__name__)


class AuthenticationError(Exception):
    pass


class TenantSelectionRequiredError(Exception):
    """Mirrors Core's own exception of the same name -- the account holds
    more than one active tenant_memberships row and the caller did not say
    which one. `tenant_ids` lets the caller present a picker, same as
    Core's own login flow does today."""

    def __init__(self, tenant_ids: list[uuid.UUID]) -> None:
        self.tenant_ids = tenant_ids
        super().__init__("Multiple tenant memberships; tenant_id is required")


async def _resolve_membership_claims(
    db: AsyncSession, *, user_id: uuid.UUID, requested_tenant_id: uuid.UUID | None,
) -> dict | None:
    """Returns the kwargs create_access_token needs for tenant/role/
    facility claims, or None for a thin (no-tenant) token -- see
    TenantMembership's own module docstring for everything this
    deliberately does not replicate from Core's fuller _resolve_claims
    (multi-role stacking, platform-admin-binds-to-unlisted-tenant,
    tenant_admin_unscoped_by_default)."""
    rows = (
        await db.execute(
            select(TenantMembership).where(
                TenantMembership.user_id == user_id, TenantMembership.is_active.is_(True),
            )
        )
    ).scalars().all()

    if requested_tenant_id is not None:
        membership = next((m for m in rows if m.tenant_id == requested_tenant_id), None)
        if membership is None:
            raise AuthenticationError("No active membership for the requested tenant")
    elif len(rows) == 1:
        membership = rows[0]
    elif not rows:
        return None
    else:
        raise TenantSelectionRequiredError([m.tenant_id for m in rows])

    return {
        "tenant_id": membership.tenant_id, "tenant_slug": membership.tenant_slug,
        "role": membership.role_name, "archetype": membership.role_archetype,
        "facility_ids": membership.facility_ids,
    }


async def login(
    db: AsyncSession, *, identifier: str, password: str,
    tenant_id: uuid.UUID | None = None,
    user_agent: str | None = None, ip_address: str | None = None,
) -> tuple[str, str]:
    # `identifier` (email) matches exactly, unchanged -- `username` matches
    # case-insensitively, mirroring Core's own get_by_identifier so an
    # account migrated from Core keeps logging in the same way it always
    # did there, by either email or username.
    result = await db.execute(
        select(User).where(
            or_(User.identifier == identifier, func.lower(User.username) == identifier.strip().lower())
        )
    )
    user = result.scalar_one_or_none()

    # Constant-work password check regardless of whether `user` exists --
    # closes the timing side-channel found in the prior Core audit.
    password_ok = verify_password_constant_time(
        password, user.hashed_password if user is not None else None
    )

    if user is None or not password_ok:
        logger.info("login.failed", identifier=identifier, reason="invalid_credentials")
        raise AuthenticationError("Invalid credentials")

    if not user.is_active:
        logger.info("login.failed", identifier=identifier, reason="inactive")
        raise AuthenticationError("Account is deactivated")

    membership_claims = await _resolve_membership_claims(
        db, user_id=user.id, requested_tenant_id=tenant_id,
    )
    access_token, _ = create_access_token(user_id=user.id, **(membership_claims or {}))

    refresh_row = RefreshToken(
        user_id=user.id,
        expires_at=datetime.now(UTC) + timedelta(days=14),
        user_agent=user_agent, ip_address=ip_address,
    )
    db.add(refresh_row)
    await db.flush()
    refresh_token = create_refresh_token(user_id=user.id, token_id=refresh_row.id)
    await db.commit()

    logger.info("login.success", user_id=str(user.id), tenant_id=str(tenant_id) if tenant_id else None)
    return access_token, refresh_token


async def refresh(
    db: AsyncSession, *, refresh_token: str, tenant_id: uuid.UUID | None = None,
) -> tuple[str, str]:
    try:
        claims = decode_token(refresh_token, expected_type="refresh")
    except InvalidToken as exc:
        logger.info("refresh.failed", reason="invalid_token", detail=str(exc))
        raise AuthenticationError("Invalid refresh token") from exc

    token_id = uuid.UUID(claims["jti"])
    result = await db.execute(select(RefreshToken).where(RefreshToken.id == token_id))
    row = result.scalar_one_or_none()
    if row is None:
        logger.warning("refresh.failed", reason="unknown_row", jti=str(token_id))
        raise AuthenticationError("Invalid refresh token")

    if row.revoked:
        # Reuse of an already-rotated-away token: revoke the whole family
        # for this user, same as Core's own reuse-detection behavior.
        await db.execute(
            RefreshToken.__table__.update()
            .where(RefreshToken.user_id == row.user_id, RefreshToken.revoked.is_(False))
            .values(revoked=True)
        )
        await db.commit()
        logger.error("refresh.reuse_detected", user_id=str(row.user_id), jti=str(token_id))
        raise AuthenticationError("Refresh token reuse detected -- all sessions revoked")

    now = datetime.now(UTC)
    if row.expires_at <= now:
        logger.info("refresh.failed", reason="expired", jti=str(token_id))
        raise AuthenticationError("Refresh token expired")

    # Rotate: revoke this row, issue a brand-new one.
    row.revoked = True
    row.last_used_at = now
    new_row = RefreshToken(
        user_id=row.user_id, expires_at=now + timedelta(days=14),
        user_agent=row.user_agent, ip_address=row.ip_address,
    )
    db.add(new_row)
    await db.flush()

    membership_claims = await _resolve_membership_claims(
        db, user_id=row.user_id, requested_tenant_id=tenant_id,
    )
    new_access_token, _ = create_access_token(user_id=row.user_id, **(membership_claims or {}))
    new_refresh_token = create_refresh_token(user_id=row.user_id, token_id=new_row.id)
    await db.commit()

    logger.info("refresh.success", user_id=str(row.user_id))
    return new_access_token, new_refresh_token


async def logout(
    db: AsyncSession, redis: Redis, *, refresh_token: str, all_devices: bool = False,
) -> None:
    try:
        claims = decode_token(refresh_token, expected_type="refresh")
    except InvalidToken:
        # Already-invalid token: nothing to revoke, logout is a no-op success.
        logger.info("logout.noop", reason="invalid_token")
        return

    token_id = uuid.UUID(claims["jti"])
    result = await db.execute(select(RefreshToken).where(RefreshToken.id == token_id))
    row = result.scalar_one_or_none()
    if row is None:
        return

    if all_devices:
        await db.execute(
            RefreshToken.__table__.update()
            .where(RefreshToken.user_id == row.user_id)
            .values(revoked=True)
        )
    else:
        row.revoked = True
    await db.commit()

    # Only an explicit "log out everywhere" should end every other active
    # session's access token. Concurrent logins across devices/tabs are
    # intended platform behavior (confirmed 2026-09-23) -- calling this
    # unconditionally meant one ordinary single-device logout silently ended
    # every other session for that account, which is exactly what surfaced as
    # unexplained logouts on a shared/test account used from multiple places
    # at once. An ordinary logout here still revokes its own refresh token
    # above; its access token dies at its own expiry, same as before this
    # revocation mechanism existed.
    if all_devices:
        await revoke_user_sessions(redis, str(row.user_id))
    logger.info("logout.success", user_id=str(row.user_id), all_devices=all_devices)


async def verify_access_token(redis: Redis, token: str) -> dict:
    """Decode + check the per-user Redis revocation marker (logout).
    Raises InvalidToken if the signature/claims are invalid OR the
    session was revoked after this token was issued.
    """
    claims = decode_token(token, expected_type="access")
    revoked = await is_session_revoked(
        redis, user_id=claims["sub"], issued_at=claims["iat"].timestamp()
        if hasattr(claims["iat"], "timestamp") else float(claims["iat"]),
    )
    if revoked:
        raise InvalidToken("session revoked")
    return claims


async def get_identifier(db: AsyncSession, *, user_id: str) -> str | None:
    """The identifier this user originally logged in with -- added for
    GET /auth/me (Phase 4I-1), purely for a caller to display something
    human-readable. Never used for verification or authorization, which
    read only the token's own `sub`. None only if `sub` resolves to no
    User row at all, which a verified token already makes effectively
    impossible (there is nothing else `sub` could have come from)."""
    user = await db.get(User, uuid.UUID(user_id))
    return user.identifier if user is not None else None
