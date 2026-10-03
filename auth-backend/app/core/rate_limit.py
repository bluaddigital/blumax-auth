"""Per-client-IP fixed-window login throttle -- same shape as Core's own
app/core/rate_limit.py (not reinvented). IP-keyed, not account-keyed (see
MIGRATION.md security findings: account-level lockout is a named,
deliberately-deferred follow-up, not silently skipped).
"""
from __future__ import annotations

from redis.asyncio import Redis

from app.core.config import settings


class RateLimitExceeded(Exception):
    pass


async def check_rate_limit(
    redis: Redis, key: str, *,
    max_attempts: int = settings.LOGIN_RATE_LIMIT_MAX_ATTEMPTS,
    window_seconds: int = settings.LOGIN_RATE_LIMIT_WINDOW_SECONDS,
) -> None:
    count = await redis.incr(key)
    if count == 1:
        await redis.expire(key, window_seconds)
    if count > max_attempts:
        raise RateLimitExceeded(f"rate limit exceeded for {key!r}: {count} > {max_attempts}")
