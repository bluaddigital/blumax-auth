"""Short-lived, single-use password-reset codes -- the SAME primitive as
an SSO code (see app/core/sso_code.py: secrets.token_urlsafe(32), Redis
GETDEL for atomic single-use consumption, fail-closed on a Redis error),
reused rather than reinvented, under its own key prefix and TTL so the
two code spaces can never collide or be confused.
"""
from __future__ import annotations

import secrets

from redis.asyncio import Redis

from app.core.config import settings

_PREFIX = "password_reset_code"


class PasswordResetUnavailableError(Exception):
    """Redis could not be reached. Same reasoning as SsoCodeUnavailableError:
    a distinct exception so the API layer can return 503, not 401/400 --
    this is a transient-infrastructure failure, not "wrong/expired code"."""


def _key(code: str) -> str:
    return f"{_PREFIX}:{code}"


async def mint_reset_code(redis: Redis, *, user_id: str) -> str:
    code = secrets.token_urlsafe(32)
    try:
        await redis.set(_key(code), user_id, ex=settings.PASSWORD_RESET_TTL_SECONDS)
    except Exception as exc:
        raise PasswordResetUnavailableError("Redis unavailable while minting reset code") from exc
    return code


async def consume_reset_code(redis: Redis, code: str) -> str | None:
    """Returns the user_id the code was minted for, or None for an
    unknown/expired/already-used code -- single-use via atomic GETDEL,
    same guarantee as an SSO code: a replay (including a concurrent one)
    can succeed at most once."""
    try:
        return await redis.getdel(_key(code))
    except Exception as exc:
        raise PasswordResetUnavailableError("Redis unavailable while consuming reset code") from exc
