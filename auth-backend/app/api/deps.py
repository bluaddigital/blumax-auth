from __future__ import annotations

import uuid
from collections.abc import AsyncGenerator

import redis.asyncio as aioredis
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.database import AsyncSessionLocal

_redis: aioredis.Redis | None = None
_bearer = HTTPBearer(auto_error=False)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async with AsyncSessionLocal() as session:
        yield session


def get_redis() -> aioredis.Redis:
    global _redis
    if _redis is None:
        _redis = aioredis.from_url(settings.REDIS_URL, decode_responses=True)
    return _redis


def bearer_token(credentials: HTTPAuthorizationCredentials | None = Depends(_bearer)) -> str:
    if credentials is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Missing bearer token")
    return credentials.credentials


async def require_human_user_id(
    token: str = Depends(bearer_token), redis: aioredis.Redis = Depends(get_redis),
) -> str:
    """A verified, non-revoked HUMAN access token's `sub`. Reuses
    auth_service.verify_access_token (the same signature/type/revocation
    checks `/auth/me` already applies) rather than re-implementing them --
    a service token presented here is rejected by the SAME expected_type
    check decode_token already enforces (see app/core/security.py)."""
    from app.core.security import InvalidToken
    from app.services import auth_service

    try:
        claims = await auth_service.verify_access_token(redis, token)
    except InvalidToken as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, str(exc)) from exc
    return claims["sub"]


async def require_service_account(
    token: str = Depends(bearer_token), db: AsyncSession = Depends(get_db),
):
    """A verified SERVICE token's ServiceAccount row, freshly re-loaded
    from the database (not trusted from the token alone) so a
    deactivated-since-mint account is rejected even if its short-lived
    token hasn't expired yet -- the same "re-resolve fresh" principle
    Core's own service-token authorization uses."""
    from app.core.security import InvalidToken, decode_token
    from app.models.service_account import ServiceAccount

    try:
        claims = decode_token(token, expected_type="service")
    except InvalidToken as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, str(exc)) from exc

    account = await db.get(ServiceAccount, uuid.UUID(claims["sub"]))
    if account is None or not account.is_active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Service account is deactivated")
    return account


__all__ = [
    "bearer_token", "get_db", "get_redis", "require_human_user_id", "require_service_account",
]
