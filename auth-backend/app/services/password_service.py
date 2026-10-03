"""Self-service password lifecycle: change (authenticated) and forgot/
reset (unauthenticated, code-based).

Design choice, stated explicitly: neither change_password nor
reset_password mints a replacement token in the same call. Both simply
revoke every existing session (forcing a fresh login everywhere) and
return 204. This sidesteps the classic "I changed my password and
immediately got logged out by my own request" race entirely, rather than
solving it with a jti-exemption mechanism (which the shared blumax_auth
library's session-revocation format does support, see app/core/
session_revocation.py, but which this service's own flows don't need
since they never mint-then-revoke in the same request).
"""
from __future__ import annotations

import uuid

import structlog
from redis.asyncio import Redis
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.password_reset import consume_reset_code, mint_reset_code
from app.core.security import hash_password, verify_password_constant_time
from app.core.session_revocation import revoke_user_sessions
from app.models.user import User

logger = structlog.get_logger(__name__)


class PasswordError(Exception):
    pass


async def change_password(
    db: AsyncSession, redis: Redis, *, user_id: str, current_password: str, new_password: str,
) -> None:
    user = await db.get(User, uuid.UUID(user_id))
    if user is None:
        raise PasswordError("Invalid credentials")

    if not verify_password_constant_time(current_password, user.hashed_password):
        logger.info("password.change.failed", user_id=user_id, reason="wrong_current_password")
        raise PasswordError("Invalid credentials")

    if len(new_password) < settings.PASSWORD_MIN_LENGTH:
        raise PasswordError(f"password must be at least {settings.PASSWORD_MIN_LENGTH} characters")

    user.hashed_password = hash_password(new_password)
    await db.commit()
    await revoke_user_sessions(redis, user_id)
    logger.info("password.change.success", user_id=user_id)


async def request_password_reset(db: AsyncSession, redis: Redis, *, identifier: str) -> str | None:
    """Always safe to call regardless of whether `identifier` exists --
    the route layer returns the same response either way (see routes),
    closing the account-enumeration gap a differing response would open.
    Returns the reset code ONLY so a non-production caller (see routes)
    can surface it without a real email/SMS transport existing yet; a
    production deployment must not expose this return value to the
    client -- see docs/PHASE5_BLUMAX_AUTH_CAPABILITY_COMPLETION.md's
    password-management section for why the transport step is explicitly
    out of scope for this phase."""
    result = await db.execute(select(User).where(User.identifier == identifier))
    user = result.scalar_one_or_none()
    if user is None or not user.is_active:
        logger.info("password.reset_request.noop", identifier=identifier)
        return None

    code = await mint_reset_code(redis, user_id=str(user.id))
    logger.info("password.reset_request.issued", user_id=str(user.id))
    return code


async def confirm_password_reset(
    db: AsyncSession, redis: Redis, *, reset_code: str, new_password: str,
) -> None:
    if len(new_password) < settings.PASSWORD_MIN_LENGTH:
        raise PasswordError(f"password must be at least {settings.PASSWORD_MIN_LENGTH} characters")

    user_id = await consume_reset_code(redis, reset_code)
    if user_id is None:
        raise PasswordError("Invalid or expired reset code")

    user = await db.get(User, uuid.UUID(user_id))
    if user is None or not user.is_active:
        raise PasswordError("Invalid or expired reset code")

    user.hashed_password = hash_password(new_password)
    await db.commit()
    await revoke_user_sessions(redis, user_id)
    logger.info("password.reset_confirm.success", user_id=user_id)
