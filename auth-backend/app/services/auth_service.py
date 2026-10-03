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
from sqlalchemy import select
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
from app.models.user import User

logger = structlog.get_logger(__name__)


class AuthenticationError(Exception):
    pass


async def login(
    db: AsyncSession, *, identifier: str, password: str,
    user_agent: str | None = None, ip_address: str | None = None,
) -> tuple[str, str]:
    result = await db.execute(select(User).where(User.identifier == identifier))
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

    access_token, _ = create_access_token(user_id=user.id)

    refresh_row = RefreshToken(
        user_id=user.id,
        expires_at=datetime.now(UTC) + timedelta(days=14),
        user_agent=user_agent, ip_address=ip_address,
    )
    db.add(refresh_row)
    await db.flush()
    refresh_token = create_refresh_token(user_id=user.id, token_id=refresh_row.id)
    await db.commit()

    logger.info("login.success", user_id=str(user.id))
    return access_token, refresh_token


async def refresh(db: AsyncSession, *, refresh_token: str) -> tuple[str, str]:
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

    new_access_token, _ = create_access_token(user_id=row.user_id)
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
