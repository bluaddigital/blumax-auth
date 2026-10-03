"""SSO code mint/exchange orchestration. See app/core/sso_code.py for the
underlying Redis primitive and its security properties.
"""
from __future__ import annotations

import uuid

import structlog
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.security import create_access_token, create_refresh_token
from app.core.sso_code import mint_code, consume_code
from app.models.refresh_token import RefreshToken
from app.models.service_account import ServiceAccount
from app.models.user import User
from datetime import UTC, datetime, timedelta

logger = structlog.get_logger(__name__)


class SsoError(Exception):
    """Every failure mode collapses to this one exception at the service
    layer -- callers map it to a single generic 401 (see routes), so a
    caller cannot distinguish "wrong destination" from "expired code" from
    "unknown code" by response content, only by the fact that something
    about the code was invalid."""


async def mint_code_for_self(redis: Redis, *, user_id: str, destination_app: str) -> tuple[str, int]:
    """A human mints a code for THEIR OWN sub -- no service-account scope
    check applies here, since the caller can only ever vouch for
    themselves (the one the access token's own `sub` already is)."""
    code = await mint_code(redis, user_id=user_id, destination_app=destination_app, issued_by=user_id)
    return code, settings.SSO_CODE_TTL_SECONDS


async def mint_code_on_behalf(
    redis: Redis, db: AsyncSession, *, caller: ServiceAccount, target_user_id: str, destination_app: str,
) -> tuple[str, int]:
    if not caller.can_mint_for(destination_app):
        logger.warning(
            "sso.mint_on_behalf.denied", service=caller.name, destination_app=destination_app,
        )
        raise SsoError("Not permitted to mint for this destination")

    try:
        target_uuid = uuid.UUID(target_user_id)
    except ValueError as exc:
        raise SsoError("Invalid user id") from exc

    user = await db.get(User, target_uuid)
    if user is None or not user.is_active:
        # Same generic failure as every other SSO rejection -- confirms
        # nothing about which identities exist to a caller probing ids.
        raise SsoError("User not found or inactive")

    code = await mint_code(
        redis, user_id=target_user_id, destination_app=destination_app, issued_by=caller.name,
    )
    logger.info("sso.mint_on_behalf.success", service=caller.name, destination_app=destination_app)
    return code, settings.SSO_CODE_TTL_SECONDS


async def exchange_code(
    redis: Redis, db: AsyncSession, *, caller: ServiceAccount, code: str,
) -> tuple[str, int]:
    """Service-to-service redemption: returns a fresh ACCESS token only
    (never a refresh token -- see app/core/sso_code.py's module docstring
    for why)."""
    payload = await consume_code(redis, code)
    if payload is None:
        raise SsoError("Invalid or expired code")

    if not caller.can_exchange_for(payload.destination_app):
        logger.warning(
            "sso.exchange.wrong_destination", service=caller.name, destination_app=payload.destination_app,
        )
        raise SsoError("Invalid or expired code")

    user = await db.get(User, uuid.UUID(payload.user_id))
    if user is None or not user.is_active:
        raise SsoError("Invalid or expired code")

    access_token, _ = create_access_token(user_id=user.id)
    logger.info("sso.exchange.success", service=caller.name, destination_app=payload.destination_app)
    return access_token, settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60


async def consume_code_public(
    redis: Redis, db: AsyncSession, *, code: str,
) -> tuple[str, str]:
    """The unauthenticated, browser-direct redeem path -- restricted to
    settings.SSO_PUBLIC_CONSUME_DESTINATION_APPS, and mints a FULL session
    (access + refresh) since there is no backend-to-backend hop afterward
    for the destination application to mint one itself."""
    payload = await consume_code(redis, code)
    if payload is None:
        raise SsoError("Invalid or expired code")

    if payload.destination_app not in settings.SSO_PUBLIC_CONSUME_DESTINATION_APPS:
        raise SsoError("Invalid or expired code")

    user = await db.get(User, uuid.UUID(payload.user_id))
    if user is None or not user.is_active:
        raise SsoError("Invalid or expired code")

    access_token, _ = create_access_token(user_id=user.id)
    refresh_row = RefreshToken(user_id=user.id, expires_at=datetime.now(UTC) + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS))
    db.add(refresh_row)
    await db.flush()
    refresh_token = create_refresh_token(user_id=user.id, token_id=refresh_row.id)
    await db.commit()
    logger.info("sso.consume.success", destination_app=payload.destination_app)
    return access_token, refresh_token
