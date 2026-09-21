"""Per-user session revocation — an opt-in dependency, checked against Redis.

    import blumax_auth
    from blumax_auth.session_revocation import check_session_revocation

    blumax_auth.configure_session_revocation(settings.REDIS_URL)   # once, at startup

    @router.get("/worklist")
    async def worklist(
        ctx: blumax_auth.TenantAuth,
        _: None = Depends(check_session_revocation),
    ):
        ...

Why this exists
----------------
Core (blumax-backend/app/core/session_revocation.py) writes a Redis key
`session_revoked_at:{user_id}` — an ISO timestamp — whenever force_login or
logout deliberately ends a user's OTHER sessions. Core's own
get_current_user/get_current_user_or_service already reject a token whose own
`iat` predates that marker. Every other service verifies the same RS256
tokens through this package but never talks to Core about them again per
request (see jwks.py's docstring) — so without this module, a session Core
considers revoked keeps authenticating everywhere else until the token's own
expiry (up to ~24h — human access tokens run on the daily 02:00 IST reset,
not a short rolling TTL).

This module closes that gap with a SHARED REDIS LOOKUP, not an HTTP call back
to Core: one Redis GET, keyed by the SAME `session_revoked_at:{user_id}`
string Core writes, so both sides agree on the wire format without needing to
agree on anything else. This is deliberately not modeled as an HTTP call
through require_permission's Checker — an explicit decision (see the module
that added this) to avoid adding a per-request network dependency on Core's
availability to every service, merely to ask a question the already-shared
Redis instance can answer directly.

Additive. Nothing in the rest of this package changes: require_auth,
require_tenant, require_role, require_archetype, require_permission and
AuthContext's existing fields are untouched (AuthContext gains one new field,
`issued_at`, defaulted so every existing construction keeps working), and no
existing route is affected until a service opts in by (1) calling
configure_session_revocation() at startup and (2) adding the
check_session_revocation dependency to a route.

The comparison logic: exact jti-exemption, not a timing grace window
----------------------------------------------------------------------
Mirrors blumax-backend's own is_session_revoked (app/core/session_revocation.py)
so the two sides can never disagree on an edge case.

An earlier version of this module (and of Core's own) compared `issued_at` to
the revocation marker with a small grace-window fudge factor, to work around
a JWT `iat` being whole-seconds precision (NumericDate truncation, RFC 7519
§2): AuthService.login's force_login branch revokes every existing session
and then, in the same call, mints the caller's OWN brand-new access token —
close enough in time that the marker and the new token's `iat` could round to
the same second.

That grace window was wrong, not just imprecise: it is symmetric, so any
session — not only the brand-new one that call was about to mint — whose
`iat` happened to fall within a couple of seconds of the revocation write was
also spared. Login (session A) followed by a force_login (session B) seconds
later is the ORDINARY case, not a rare race, so the grace window routinely
protected the very session force_login exists to end.

The actual ambiguous case is narrow and exactly identifiable: the one new
token that same force_login call is about to mint. Core doesn't infer that
from timestamps at all — it knows that token's `jti` the instant
create_access_token returns it, and writes an explicit exemption marker,
`session_revoked_at:{user_id}:exempt:{jti}`, right after minting it. This
module's job is only ever the READ side of that: this is a consuming
service, never the one calling force_login or writing either marker. So
is_session_revoked here checks the exemption key first (if present, the
token is never revoked — no timing involved), and otherwise falls back to a
plain, STRICT `issued_at` comparison with no slack: `issued_at <= revoked_at`
means revoked, full stop. Every session other than an explicitly exempted one
is revoked, regardless of how close in time it was issued.

Fail open, on purpose
----------------------
Matching every other fail-open posture in this package (an unreachable JWKS
endpoint keeps serving its last-cached keys — require_permission's
Core-unavailable path is the one deliberate exception, and it says so loudly
in its own docstring): a Redis outage here is read as "nothing to revoke",
never as a reason to reject the request. This check is a security
IMPROVEMENT layered on top of signature/expiry verification, never a
replacement for it — losing the shared Redis must not turn into an outage of
its own for every service that opted in.

Rollout mode
------------
`mode="warn"` (the default, service-wide, set at configure_session_revocation
time) runs the same check but rejects nothing, and records every decision as
one `session_revocation_check` log event so a service can watch what
enforcement WOULD do before turning it on:

    decision  allow          not revoked (no marker, exempted jti,           INFO
                              or the check could not be meaningfully applied
                              — e.g. no issued_at on the token)
              would_reject   revoked: iat at or before the marker, and       WARNING
                              not exempted
              check_failed   the check itself could not complete             WARNING
                             (see `reason`: redis_unavailable | marker_malformed)

Fields (all plain scalars; never a token): decision, reason (only when not a
plain allow: not_configured | redis_unavailable | marker_malformed |
no_issued_at), mode, user_id, and revoked_at (only when a marker was read and
found revoked).

`mode="enforce"` raises the same kind of 401 require_auth already raises on
an invalid token (blumax_auth.errors.InvalidToken) when the session is
revoked. Enforce mode logs nothing; a rejection is the 401 the caller
receives — matching require_permission's own convention that the mode only
governs the check's own decision, never authentication itself.

Authentication failures raised upstream (bad token, wrong tenant) are
unaffected by this check either way — it only ever runs after require_auth
has already produced a verified AuthContext, via its own Depends(require_auth).

The events are emitted through the stdlib logger
`blumax_auth.session_revocation` with the fields as `extra`. A service that
renders logs through structlog must include `structlog.stdlib.ExtraAdder()`
in its ProcessorFormatter's foreign_pre_chain, or the fields are silently
dropped — the same note as permissions.py's own docstring.
"""
from __future__ import annotations

import contextlib
import logging
from datetime import datetime
from typing import TYPE_CHECKING, Annotated, Literal

from fastapi import Depends

from blumax_auth.context import AuthContext
from blumax_auth.errors import InvalidToken
from blumax_auth.fastapi import require_auth

if TYPE_CHECKING:
    from redis.asyncio import Redis

_log = logging.getLogger("blumax_auth.session_revocation")

Mode = Literal["enforce", "warn"]


def _key(user_id: object) -> str:
    # Same format Core writes: f"session_revoked_at:{user_id}". user_id is
    # whatever AuthContext carries (a uuid.UUID); str() renders it the same
    # way Core's own str(user_id) does.
    return f"session_revoked_at:{user_id}"


def _exempt_key(user_id: object, jti: str) -> str:
    # Same format Core writes: f"session_revoked_at:{user_id}:exempt:{jti}"
    # (app/core/session_revocation.py::_exempt_key), written once by
    # AuthService.login's force_login branch right after minting its own new
    # access token, so that token's own jti is spared from the revocation it
    # just triggered.
    return f"session_revoked_at:{user_id}:exempt:{jti}"


class _Checker:
    """One configured Redis connection plus the mode it defaults to."""

    def __init__(self, redis: Redis, *, mode: Mode) -> None:
        self.redis = redis
        self.mode = mode

    async def is_revoked(
        self, user_id: object, issued_at: datetime | None, jti: str | None
    ) -> tuple[bool, str | None, datetime | None]:
        """Returns (revoked, reason_if_ambiguous, revoked_at_if_known).

        Mirrors blumax-backend's is_session_revoked: checks the exemption key
        first (if `jti` was explicitly exempted, never revoked — no timing
        involved), then falls back to a strict, no-grace `issued_at`
        comparison. False (never revoked) on every kind of ambiguity — no
        issued_at to compare, no marker set, Redis unreachable, or a
        malformed marker. This is a READ-only mirror: this service never
        writes either the revocation marker or an exemption — only Core does
        (via force_login/logout).
        """
        if issued_at is None:
            return False, "no_issued_at", None

        if jti is not None:
            try:
                if await self.redis.get(_exempt_key(user_id, jti)):
                    return False, None, None
            except Exception:
                _log.warning(
                    "session_revocation_exemption_check_unavailable",
                    extra={"user_id": str(user_id)},
                )
                # Fall through to the ordinary marker check below rather than
                # returning early — a broken Redis client will fail that
                # check too and fail open there, the one shared fail-open
                # path this module guarantees.

        try:
            raw = await self.redis.get(_key(user_id))
        except Exception:
            _log.warning("session_revocation_check_unavailable", extra={"user_id": str(user_id)})
            return False, "redis_unavailable", None
        if not raw:
            return False, None, None
        try:
            revoked_at = datetime.fromisoformat(raw)
        except ValueError:
            _log.warning("session_revocation_marker_malformed", extra={"user_id": str(user_id)})
            return False, "marker_malformed", None
        revoked = issued_at <= revoked_at
        return revoked, None, revoked_at


_checker: _Checker | None = None


def configure_session_revocation(redis_url: str, *, mode: Mode = "warn") -> None:
    """Point this service at the shared Redis for session-revocation checks.

    Call once, at service startup — the same shape as configure_permissions().
    Connects via redis.asyncio (an optional dependency of this package,
    imported here rather than at module load time, so services that never
    call this function need not install it), the same client blumax-backend
    itself uses for this purpose (app/core/redis.py), so both sides read/
    write the identical key format over the identical protocol.

    redis_url  A redis:// / rediss:// connection URL for the SAME Redis
               instance Core writes session_revoked_at:{user_id} (and its
               exemption keys) to. Sharing that instance (not merely the key
               format) is what makes this a same-process GET rather than a
               network call to Core.
    mode       "warn" (default) or "enforce" — see the module docstring's
               "Rollout mode" section. check_session_revocation() honors
               whichever was set here.
    """
    global _checker
    if not redis_url or not redis_url.strip():
        raise ValueError("redis_url is required")
    if mode not in ("enforce", "warn"):
        raise ValueError(f"mode must be 'enforce' or 'warn', got {mode!r}")

    import redis.asyncio as aioredis  # noqa: PLC0415 — optional dep, only needed if this is used

    _checker = _Checker(aioredis.Redis.from_url(redis_url, decode_responses=True), mode=mode)


async def aclose_session_revocation() -> None:
    """Close the Redis connection. Call from the app's shutdown hook."""
    if _checker is not None:
        with contextlib.suppress(Exception):
            await _checker.redis.aclose()


def reset_session_revocation() -> None:
    """Drop the session-revocation configuration. Tests only."""
    global _checker
    _checker = None


async def check_session_revocation(
    ctx: Annotated[AuthContext, Depends(require_auth)],
) -> None:
    """FastAPI dependency: reject (or, in warn mode, merely log) a caller
    whose session Core has revoked.

    Add this alongside require_auth/require_tenant/require_permission on any
    route that should honor Core's force_login/logout revocation. It is
    itself additive — a route that doesn't depend on it is entirely
    unaffected — and it never widens what require_auth already verified; it
    can only narrow (enforce mode) or observe (warn mode) it further.

    The mode is whatever configure_session_revocation() was given; there is
    no per-route override, matching the request that this be a simple opt-in
    switch a service flips once, service-wide, exactly like
    configure_permissions()'s own mode staging is meant to be watched in warn
    before a service turns enforcement on.

    enforce: raises InvalidToken (401) if the caller's token is revoked —
             its jti is not exempted, and its issued_at is at or before a
             revocation marker for its user.
    warn:    performs the same check, logs a session_revocation_check event,
             and never rejects.

    Unconfigured: warn mode logs check_failed/not_configured and passes. If
    no mode has ever been configured there is no way to tell what the caller
    intended, so this treats "unconfigured" as warn's own behavior — passing
    but logging — rather than guessing enforce; a service that truly wants
    enforcement calls configure_session_revocation(mode="enforce") and this
    path is never reached.
    """
    checker = _checker
    if checker is None:
        _emit(ctx, decision="check_failed", reason="not_configured")
        return

    revoked, reason, revoked_at = await checker.is_revoked(ctx.user_id, ctx.issued_at, ctx.jti)

    if reason is not None:
        # Ambiguous outcomes are never revoked (fail-open). In warn mode,
        # distinguish a real check failure (redis_unavailable /
        # marker_malformed) from a check that simply didn't apply
        # (no_issued_at) so the log is honest about which happened —
        # both already resolve to "not rejected" either way.
        if checker.mode == "warn":
            decision = "check_failed" if reason in ("redis_unavailable", "marker_malformed") else "allow"
            _emit(ctx, decision=decision, reason=reason)
        return

    if revoked:
        if checker.mode == "warn":
            _emit(ctx, decision="would_reject", revoked_at=revoked_at)
            return
        raise InvalidToken("Session has been revoked")

    if checker.mode == "warn":
        _emit(ctx, decision="allow")
    return


def _emit(
    ctx: AuthContext,
    *,
    decision: str,
    reason: str | None = None,
    revoked_at: datetime | None = None,
) -> None:
    """One `session_revocation_check` event. Plain scalars only: no token."""
    extra: dict[str, object] = {
        "decision": decision,
        "mode": "warn",
        "user_id": str(ctx.user_id),
    }
    if reason is not None:
        extra["reason"] = reason
    if revoked_at is not None:
        extra["revoked_at"] = revoked_at.isoformat()
    _log.log(
        logging.INFO if decision == "allow" else logging.WARNING,
        "session_revocation_check",
        extra=extra,
    )
