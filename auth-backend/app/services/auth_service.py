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

from app.core.config import settings
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
from app.models.tenant_namespace import TenantNamespace, normalize_slug
from app.models.user import User, normalize_identifier

logger = structlog.get_logger(__name__)

# Mirrors Core's own blumax-backend/app/modules/identity/application/
# services.py::_REUSE_GRACE_WINDOW exactly -- same value, same reasoning,
# no stated need to diverge. See refresh()'s own comment at the one place
# this is used.
_REUSE_GRACE_WINDOW = timedelta(seconds=10)


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


async def resolve_tenant_ref(db: AsyncSession, tenant: str) -> uuid.UUID | None:
    """A login's tenant reference -- the platform tenant UUID, or the
    hospital code / tenant slug registered in tenant_namespaces. None when
    the slug is unknown (callers answer exactly as for a wrong password,
    so an unknown hospital code is not distinguishable)."""
    raw = tenant.strip()
    try:
        return uuid.UUID(raw)
    except ValueError:
        pass
    return (
        await db.execute(
            select(TenantNamespace.tenant_id).where(TenantNamespace.slug == normalize_slug(raw))
        )
    ).scalar_one_or_none()


async def _tenant_slug(db: AsyncSession, tenant_id: uuid.UUID) -> str | None:
    return (
        await db.execute(select(TenantNamespace.slug).where(TenantNamespace.tenant_id == tenant_id))
    ).scalar_one_or_none()


async def _tenant_scoped_claims(
    db: AsyncSession, *, user: User, requested_tenant_id: uuid.UUID | None,
) -> dict:
    """Claims for a tenant-scoped account: the token carries exactly ONE
    tenant -- the account's own -- and `sub` is that tenant's account id.
    A request naming any other tenant is refused (no cross-tenant
    switching, owner decision 2026-11-28). Role/facility claims come only
    from an active membership row for that same tenant; membership rows for
    any other tenant are never consulted. Without one, the token is bound
    to the tenant with the most restrictive claims (VIEWER, no facility)."""
    if requested_tenant_id is not None and requested_tenant_id != user.tenant_id:
        raise AuthenticationError("No active membership for the requested tenant")
    membership = (
        await db.execute(
            select(TenantMembership).where(
                TenantMembership.user_id == user.id,
                TenantMembership.tenant_id == user.tenant_id,
                TenantMembership.is_active.is_(True),
            )
        )
    ).scalar_one_or_none()
    slug = await _tenant_slug(db, user.tenant_id)
    if membership is None:
        return {
            "tenant_id": user.tenant_id, "tenant_slug": slug,
            "role": None, "archetype": "VIEWER", "facility_ids": [],
        }
    return {
        "tenant_id": user.tenant_id, "tenant_slug": slug or membership.tenant_slug,
        "role": membership.role_name, "archetype": membership.role_archetype,
        "facility_ids": membership.facility_ids,
    }


async def _claims_for_user(
    db: AsyncSession, *, user: User, requested_tenant_id: uuid.UUID | None,
) -> dict | None:
    if user.tenant_id is not None:
        return await _tenant_scoped_claims(db, user=user, requested_tenant_id=requested_tenant_id)
    return await _resolve_membership_claims(db, user_id=user.id, requested_tenant_id=requested_tenant_id)


def _legacy_user_stmt(identifier: str):
    # `identifier` (email) matches exactly, unchanged -- `username` matches
    # case-insensitively, mirroring Core's own get_by_identifier so an
    # account migrated from Core keeps logging in the same way it always
    # did there, by either email or username. Global (tenant_id IS NULL)
    # rows only: a tenant-scoped account is never reachable without naming
    # its tenant (and the same username may exist in several tenants).
    return select(User).where(
        User.tenant_id.is_(None),
        or_(User.identifier == identifier, func.lower(User.username) == identifier.strip().lower()),
    )


async def find_tenant_user(db: AsyncSession, *, tenant_id: uuid.UUID, identifier: str) -> User | None:
    """The tenant-scoped account in `tenant_id` whose identifier or
    username matches (both normalized). Never looks outside that tenant."""
    norm = normalize_identifier(identifier)
    rows = (
        await db.execute(
            select(User).where(
                User.tenant_id == tenant_id,
                or_(User.identifier == norm, User.username_normalized == norm),
            )
        )
    ).scalars().all()
    # Creation refuses an identifier/username that collides with either
    # column of another account in the same tenant; prefer the identifier
    # match anyway in case older rows overlap.
    for row in rows:
        if row.identifier == norm:
            return row
    return rows[0] if rows else None


async def login(
    db: AsyncSession, *, identifier: str, password: str,
    tenant_id: uuid.UUID | None = None, tenant: str | None = None,
    user_agent: str | None = None, ip_address: str | None = None,
) -> tuple[str, str]:
    """`tenant` (hospital code / tenant slug, or tenant UUID) is honoured
    only with TENANT_SCOPED_IDENTITY_MODE=on; with the mode off this
    function behaves exactly as before the setting existed.

    With a tenant: the account is resolved inside that tenant only. A
    tenant-scoped account wins; if none matches, a GLOBAL legacy account
    may still sign in, bound to that tenant through its active membership
    (so a hospital login page that starts sending its code does not lock
    out not-yet-migrated staff). Without a tenant: global accounts only --
    a tenant-scoped account cannot be reached."""
    if tenant is not None and tenant.strip() and settings.tenant_scoped_identity_enabled:
        return await _login_in_tenant(
            db, identifier=identifier, password=password, tenant=tenant,
            requested_tenant_id=tenant_id, user_agent=user_agent, ip_address=ip_address,
        )

    result = await db.execute(_legacy_user_stmt(identifier))
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
        expires_at=datetime.now(UTC) + _refresh_lifetime(),
        user_agent=user_agent, ip_address=ip_address,
    )
    db.add(refresh_row)
    await db.flush()
    refresh_token = create_refresh_token(user_id=user.id, token_id=refresh_row.id)
    await db.commit()

    logger.info("login.success", user_id=str(user.id), tenant_id=str(tenant_id) if tenant_id else None)
    return access_token, refresh_token


async def _issue_pair(
    db: AsyncSession, *, user: User, claims: dict | None,
    user_agent: str | None, ip_address: str | None,
) -> tuple[str, str]:
    access_token, _ = create_access_token(user_id=user.id, **(claims or {}))
    refresh_row = RefreshToken(
        user_id=user.id,
        expires_at=datetime.now(UTC) + _refresh_lifetime(),
        user_agent=user_agent, ip_address=ip_address,
    )
    db.add(refresh_row)
    await db.flush()
    refresh_token = create_refresh_token(user_id=user.id, token_id=refresh_row.id)
    await db.commit()
    return access_token, refresh_token


async def _login_in_tenant(
    db: AsyncSession, *, identifier: str, password: str, tenant: str,
    requested_tenant_id: uuid.UUID | None,
    user_agent: str | None, ip_address: str | None,
) -> tuple[str, str]:
    resolved = await resolve_tenant_ref(db, tenant)
    user: User | None = None
    if resolved is not None and (requested_tenant_id is None or requested_tenant_id == resolved):
        user = await find_tenant_user(db, tenant_id=resolved, identifier=identifier)
        if user is None:
            user = (await db.execute(_legacy_user_stmt(identifier))).scalar_one_or_none()

    # Same constant-work password check as the legacy path, whether or not
    # the tenant or the account exists.
    password_ok = verify_password_constant_time(
        password, user.hashed_password if user is not None else None
    )
    if user is None or not password_ok:
        logger.info("login.failed", identifier=identifier, reason="invalid_credentials", tenant_scoped=True)
        raise AuthenticationError("Invalid credentials")
    if not user.is_active:
        logger.info("login.failed", identifier=identifier, reason="inactive", tenant_scoped=True)
        raise AuthenticationError("Account is deactivated")

    # A tenant-scoped account is bound to its own tenant; a global legacy
    # account must hold an active membership in the named tenant
    # (_resolve_membership_claims raises otherwise) -- either way the token
    # carries exactly the tenant the login named.
    claims = await _claims_for_user(db, user=user, requested_tenant_id=resolved)
    access_token, refresh_token = await _issue_pair(
        db, user=user, claims=claims, user_agent=user_agent, ip_address=ip_address,
    )
    logger.info(
        "login.success", user_id=str(user.id), tenant_id=str(resolved),
        account_kind="tenant" if user.tenant_id is not None else "global",
    )
    return access_token, refresh_token


async def mint_for_verified_identity(
    db: AsyncSession, *, user_id: uuid.UUID, tenant_id: uuid.UUID | None = None,
    user_agent: str | None = None, ip_address: str | None = None,
) -> tuple[str, str]:
    """Core's own ISSUE_VIA_BLUMAX_AUTH migration flag (2026-10-25): mint a
    token pair for an identity CORE has already verified the CREDENTIAL
    for -- its own password check, temp-password expiry, platform-admin
    tenant resolution, every login business rule this service's own
    `login()` above does not yet replicate (see MIGRATION.md). Only the
    password check is skipped here; is_active is re-checked below, cheap
    defense-in-depth against this service's own sync lagging Core's by the
    few seconds between Core's check and this call -- an account
    deactivated in that window should not mint a token just because Core's
    read was a moment stale.

    Deliberately a parallel function, not login() with its password
    argument made optional: a shared function with an "already verified,
    trust me" flag is one typo away from skipping the credential check
    too. Duplicating the few-line tail once is cheaper than that risk.

    Raises AuthenticationError if user_id does not exist or is inactive
    (no token to mint for), or TenantSelectionRequiredError exactly as
    login() does -- neither can be Core's fault alone to resolve, since
    Core's own tenant_id resolution and this service's tenant_memberships
    sync could in principle have drifted; surfacing the same exception
    either way means the caller (Core) decides how to handle it, not this
    function.
    """
    user = (await db.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    if user is None:
        raise AuthenticationError("No such user")
    if not user.is_active:
        raise AuthenticationError("Account is deactivated")

    membership_claims = await _claims_for_user(db, user=user, requested_tenant_id=tenant_id)
    access_token, _ = create_access_token(user_id=user.id, **(membership_claims or {}))

    refresh_row = RefreshToken(
        user_id=user.id,
        expires_at=datetime.now(UTC) + _refresh_lifetime(),
        user_agent=user_agent, ip_address=ip_address,
    )
    db.add(refresh_row)
    await db.flush()
    refresh_token = create_refresh_token(user_id=user.id, token_id=refresh_row.id)
    await db.commit()

    logger.info(
        "mint_for_verified_identity.success",
        user_id=str(user.id), tenant_id=str(tenant_id) if tenant_id else None,
    )
    return access_token, refresh_token


def _refresh_lifetime() -> timedelta:
    """Refresh-row lifetime: the configured REFRESH_TOKEN_EXPIRE_DAYS (default 14), the same value the refresh
    JWT's own `exp` uses, so the row and the token cannot disagree."""
    return timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)


def revoke_all_refresh_tokens_stmt(user_id: uuid.UUID):
    """UPDATE that revokes every live refresh row of a user. The caller executes it in its own transaction (so a
    password change and the revocation commit together) and then writes the Redis marker for access tokens."""
    return (
        RefreshToken.__table__.update()
        .where(RefreshToken.user_id == user_id, RefreshToken.revoked.is_(False))
        .values(revoked=True)
    )


async def refresh(
    db: AsyncSession, *, refresh_token: str, tenant_id: uuid.UUID | None = None, redis: Redis | None = None,
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
        # A token presented moments after its OWN rotation is not always
        # theft -- it's also what any OTHER tab/app sharing this session
        # looks like when it loses a race to rotate the same refresh
        # token (each tab only single-flights its own refresh calls;
        # separate tabs/apps have separate JS module instances and don't
        # know about each other). Core's own AuthService.refresh() hit
        # this exact bug live and fixed it the same way this does:
        # distinguish "the losing side of an ordinary race" from real
        # reuse by checking whether the rotation happened moments ago
        # AND a legitimately newer session already exists for this user.
        # A real thief replaying a stolen token has no reason to also
        # have a newer, live session already active, so this narrows
        # the exemption to the one case with an innocent explanation --
        # it does not weaken detection of an actual stolen/replayed
        # token (see test_replay_with_no_newer_session_still_nukes_the_family).
        recently_revoked = row.last_used_at is not None and (
            datetime.now(UTC) - row.last_used_at < _REUSE_GRACE_WINDOW
        )
        if recently_revoked:
            newer_session = await db.execute(
                select(RefreshToken.id).where(
                    RefreshToken.user_id == row.user_id,
                    RefreshToken.revoked.is_(False),
                    RefreshToken.expires_at > datetime.now(UTC),
                ).limit(1)
            )
            if newer_session.scalar_one_or_none() is not None:
                logger.info(
                    "refresh.late_reuse_after_rotation",
                    user_id=str(row.user_id), jti=str(token_id),
                )
                raise AuthenticationError("Invalid refresh token")

        # Reuse of an already-rotated-away token, with no such innocent
        # explanation: revoke the whole family for this user, same as
        # Core's own reuse-detection behavior.
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

    # An account that was deactivated (or removed) after this token was issued must not keep minting access
    # tokens (audit D-6). Its whole refresh family is ended, durably, in the same transaction.
    user = await db.get(User, row.user_id)
    if user is None or not user.is_active:
        await db.execute(revoke_all_refresh_tokens_stmt(row.user_id))
        await db.commit()
        logger.info("refresh.failed", reason="inactive_user", user_id=str(row.user_id), jti=str(token_id))
        raise AuthenticationError("Account is deactivated")

    # The shared Redis marker (written by Core's force_login/logout and by this service's own revocations) also
    # ends a refresh token whose row was created at or before it. Compared against the row's own full-precision
    # created_at, not the JWT's whole-second iat, so a login right after a revocation is not caught by rounding.
    # An unreachable/malformed marker follows SESSION_REVOCATION_FAIL_MODE exactly like the access-token check.
    if redis is not None and await is_session_revoked(
        redis, user_id=str(row.user_id), issued_at=row.created_at.timestamp(),
    ):
        logger.info("refresh.failed", reason="session_revoked", user_id=str(row.user_id), jti=str(token_id))
        raise AuthenticationError("Session has been revoked")

    # Rotate: revoke this row, issue a brand-new one.
    row.revoked = True
    row.last_used_at = now
    new_row = RefreshToken(
        user_id=row.user_id, expires_at=now + _refresh_lifetime(),
        user_agent=row.user_agent, ip_address=row.ip_address,
    )
    db.add(new_row)
    await db.flush()

    # A tenant-scoped account's refresh stays bound to its own tenant: a
    # refresh naming another tenant is refused, never re-bound.
    membership_claims = await _claims_for_user(db, user=user, requested_tenant_id=tenant_id)
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
