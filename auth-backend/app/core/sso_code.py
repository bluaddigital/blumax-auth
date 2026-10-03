"""Short-lived, single-use SSO authorization codes.

Reimplemented against Blumax Auth's own architecture, not copied from
Core -- but adopting the same proven security parameters where nothing
about this service's design argues for a different choice (256 bits of
entropy, GETDEL-based atomic single-use consumption, a short fixed TTL,
fail-closed on a Redis error). What's different from Core's version,
deliberately:

- Blumax Auth has no tenant concept, so a code's payload carries no
  tenant_id -- only the user being vouched for and the destination
  application.
- Which services may mint-on-behalf / exchange for which destinations is
  resolved against this service's OWN ServiceAccount table (see
  app/models/service_account.py), not a hardcoded dict of service names --
  Blumax Auth is meant to be the platform's single, generic SSO authority
  for every current and future application (Admin/Core/OPD/IPD/Labs/
  Pharmacy...), not pre-wired to a fixed, small set of known services the
  way Core's current implementation is.

Security properties, each independently testable (see tests/test_sso.py):
  - 256 bits of entropy (secrets.token_urlsafe(32)) -- not guessable.
  - Single-use: consumption is one atomic Redis GETDEL -- a replay (the
    same code presented twice, even concurrently) can succeed at most
    once; every other attempt sees nothing to consume.
  - Short TTL (settings.SSO_CODE_TTL_SECONDS, default 60s) -- bounds how
    long a leaked-but-unconsumed code remains dangerous.
  - Fail-CLOSED on a Redis error, both minting and consuming -- the one
    deliberate exception to this service's otherwise fail-open-everywhere-
    else posture (rate limiting, session revocation): an operation this
    security-critical must never silently proceed as if Redis were
    healthy. Matches Core's own choice for the identical reason.
  - No password or refresh token is ever placed in a code's payload --
    only a user id and a destination string, both already public-ish
    within the platform (an application a human is already using already
    knows who they are); exchanging a code yields a normal, freshly-minted
    ACCESS token only, never a refresh token, so a leaked exchange
    response cannot establish a long-lived session.
"""
from __future__ import annotations

import json
import secrets
from dataclasses import dataclass

from redis.asyncio import Redis

from app.core.config import settings

_PREFIX = "sso_code"


class SsoCodeUnavailableError(Exception):
    """Redis could not be reached while minting or consuming a code.
    Deliberately a DIFFERENT exception from "code invalid/expired" so the
    API layer can return 503 (try again) rather than 401 (this code will
    never work) -- collapsing the two would make a transient Redis blip
    indistinguishable from an attacker's guess, which is itself a minor
    information leak in the failure-mode's shape, and unhelpful to a
    legitimate caller who should simply retry."""


@dataclass(frozen=True)
class SsoCodePayload:
    user_id: str
    destination_app: str
    issued_by: str | None  # audit-only: the minting human's own sub, or
    # the vouching service account's name. Never trust-bearing -- every
    # authorization decision at exchange time is re-checked against live
    # DB state, never inferred from this field.


def _key(code: str) -> str:
    return f"{_PREFIX}:{code}"


async def mint_code(
    redis: Redis, *, user_id: str, destination_app: str, issued_by: str | None,
) -> str:
    code = secrets.token_urlsafe(32)
    payload = SsoCodePayload(user_id=user_id, destination_app=destination_app, issued_by=issued_by)
    body = json.dumps(
        {"user_id": payload.user_id, "destination_app": payload.destination_app, "issued_by": payload.issued_by}
    )
    try:
        await redis.set(_key(code), body, ex=settings.SSO_CODE_TTL_SECONDS)
    except Exception as exc:
        raise SsoCodeUnavailableError("Redis unavailable while minting SSO code") from exc
    return code


async def consume_code(redis: Redis, code: str) -> SsoCodePayload | None:
    """Atomic read+delete -- a concurrent second consumption of the SAME
    code is guaranteed to observe nothing (GETDEL is a single Redis
    command; Redis itself serializes commands, so there is no window for
    two callers to both see the payload). Returns None for an unknown,
    expired, or already-consumed code -- every one of those is
    indistinguishable from the others by design, so a caller cannot use
    response differences to probe which codes once existed."""
    try:
        raw = await redis.getdel(_key(code))
    except Exception as exc:
        raise SsoCodeUnavailableError("Redis unavailable while consuming SSO code") from exc
    if raw is None:
        return None
    try:
        data = json.loads(raw)
        return SsoCodePayload(
            user_id=data["user_id"], destination_app=data["destination_app"], issued_by=data.get("issued_by"),
        )
    except (ValueError, KeyError):
        return None
