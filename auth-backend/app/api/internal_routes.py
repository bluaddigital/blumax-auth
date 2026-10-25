from __future__ import annotations

import hmac

from fastapi import APIRouter, Depends, Header, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db
from app.core.config import settings
from app.schemas.internal import MembershipRevokedRequest, MembershipSyncRequest, UserSyncRequest
from app.services.membership_sync_service import revoke_membership_from_core, sync_membership_from_core
from app.services.user_sync_service import UserSyncConflictError, sync_user_from_core

internal_router = APIRouter(prefix="/internal", tags=["internal"])


def require_core_user_sync_key(
    x_blumax_auth_user_sync_key: str | None = Header(default=None),
) -> None:
    """Static shared-secret check -- see CORE_USER_SYNC_SERVICE_KEY's own
    docstring in config.py for why this is a header, not this service's own
    OAuth-style service token. hmac.compare_digest: a single, fixed,
    platform-internal caller, same constant-time-comparison posture this
    service already uses for password verification."""
    if not x_blumax_auth_user_sync_key or not hmac.compare_digest(
        x_blumax_auth_user_sync_key, settings.CORE_USER_SYNC_SERVICE_KEY,
    ):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or missing sync key")


@internal_router.post(
    "/users/sync",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(require_core_user_sync_key)],
)
async def sync_user_route(
    body: UserSyncRequest, db: AsyncSession = Depends(get_db),
) -> None:
    try:
        await sync_user_from_core(
            db, user_id=body.user_id, identifier=body.identifier,
            username=body.username, hashed_password=body.hashed_password,
            is_active=body.is_active,
        )
    except UserSyncConflictError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc


@internal_router.post(
    "/memberships/sync",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(require_core_user_sync_key)],
)
async def sync_membership_route(
    body: MembershipSyncRequest, db: AsyncSession = Depends(get_db),
) -> None:
    await sync_membership_from_core(
        db, user_id=body.user_id, tenant_id=body.tenant_id, tenant_slug=body.tenant_slug,
        role_name=body.role_name, role_archetype=body.role_archetype,
        facility_ids=body.facility_ids,
    )


@internal_router.post(
    "/memberships/revoke",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(require_core_user_sync_key)],
)
async def revoke_membership_route(
    body: MembershipRevokedRequest, db: AsyncSession = Depends(get_db),
) -> None:
    await revoke_membership_from_core(db, user_id=body.user_id, tenant_id=body.tenant_id)
