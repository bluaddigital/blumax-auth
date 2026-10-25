from __future__ import annotations

import hmac

from fastapi import APIRouter, Depends, Header, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db
from app.core.config import settings
from app.schemas.internal import (
    MembershipRevokedRequest,
    MembershipSyncRequest,
    MintForVerifiedIdentityRequest,
    MintForVerifiedIdentityResponse,
    UserSyncRequest,
)
from app.services.auth_service import (
    AuthenticationError,
    TenantSelectionRequiredError,
    mint_for_verified_identity,
)
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


def require_core_token_mint_key(
    x_blumax_auth_token_mint_key: str | None = Header(default=None),
) -> None:
    """Same shared-secret posture as require_core_user_sync_key above, but a
    DIFFERENT key (CORE_TOKEN_MINT_SERVICE_KEY) -- see that setting's own
    docstring for why a token-minting capability must never share a secret
    with the sync-only one."""
    if not x_blumax_auth_token_mint_key or not hmac.compare_digest(
        x_blumax_auth_token_mint_key, settings.CORE_TOKEN_MINT_SERVICE_KEY,
    ):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or missing token-mint key")


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


@internal_router.post(
    "/tokens/mint-for-verified-identity",
    response_model=MintForVerifiedIdentityResponse,
    dependencies=[Depends(require_core_token_mint_key)],
)
async def mint_for_verified_identity_route(
    body: MintForVerifiedIdentityRequest, db: AsyncSession = Depends(get_db),
) -> MintForVerifiedIdentityResponse:
    try:
        access_token, refresh_token = await mint_for_verified_identity(
            db, user_id=body.user_id, tenant_id=body.tenant_id,
            user_agent=body.user_agent, ip_address=body.ip_address,
        )
    except TenantSelectionRequiredError as exc:
        # Same shape as this service's own public /auth/login -- Core's
        # caller decides how to handle it, this route does not resolve it.
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            {"error_code": "TENANT_SELECTION_REQUIRED", "tenant_ids": [str(t) for t in exc.tenant_ids]},
        ) from exc
    except AuthenticationError as exc:
        # 422, not 401: the CALLER (Core) is authenticated fine (the
        # service key above already gated that) -- this means the identity
        # it asked to mint for doesn't exist or isn't active here, a data
        # problem, not a credential problem.
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc
    return MintForVerifiedIdentityResponse(access_token=access_token, refresh_token=refresh_token)
