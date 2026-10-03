"""Per-user access-token revocation (for logout), backed by Redis, since
access tokens are stateless RS256 JWTs with no per-request DB check.

DELIBERATE DEPARTURE FROM CORE: the prior audit of Core's own
session_revocation.py found it fails OPEN when Redis is unreachable --
a logged-out user's still-unexpired access token is silently honoured
again. This module makes that choice explicit and configurable
(settings.SESSION_REVOCATION_FAIL_MODE, default "closed" = safer), and
always logs loudly either way -- "Do not silently ignore this" (your own
instruction). This is new, intentional behavior for this service, not a
port of Core's.

KEY FORMAT (fixed in Phase 5): the marker key is `session_revoked_at:
{user_id}` -- byte-identical to what Core writes and what the shared
blumax_auth.session_revocation library's check_session_revocation()
reads. An earlier version of this module used a service-local prefix
(`auth_session_revoked_at:*`), which meant a downstream consumer that
called configure_session_revocation() against THIS service's Redis would
silently see every logout here as "not revoked" (the library would be
reading a key this service never wrote) -- a format mismatch, not a
design choice, found during a platform-wide SSO/service-auth audit and
corrected here. Reusing Core's exact wire format is deliberate: it lets
the SAME shared-library mechanism work against either issuer's Redis
without a consumer needing to know or care which one is currently
authoritative.
"""
from __future__ import annotations

import structlog
from redis.asyncio import Redis

from app.core.config import settings

logger = structlog.get_logger(__name__)

_PREFIX = "session_revoked_at"


def _key(user_id: str) -> str:
    return f"{_PREFIX}:{user_id}"


async def revoke_user_sessions(redis: Redis, user_id: str) -> None:
    import time
    await redis.set(
        _key(user_id), str(time.time()), ex=settings.SESSION_REVOCATION_TTL_SECONDS,
    )
    logger.info("session_revocation.revoked", user_id=user_id)


async def is_session_revoked(redis: Redis, *, user_id: str, issued_at: float) -> bool:
    """True if `user_id`'s sessions were revoked at or after `issued_at`."""
    try:
        marker = await redis.get(_key(user_id))
    except Exception as exc:
        fail_closed = settings.SESSION_REVOCATION_FAIL_MODE == "closed"
        logger.error(
            "session_revocation.redis_unreachable",
            user_id=user_id, fail_mode=settings.SESSION_REVOCATION_FAIL_MODE,
            treating_as_revoked=fail_closed, error=str(exc),
        )
        return fail_closed

    if marker is None:
        return False
    revoked_at = float(marker)
    return revoked_at >= issued_at
