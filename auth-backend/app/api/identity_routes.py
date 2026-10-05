from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db, get_redis, require_service_account
from app.models.service_account import ServiceAccount
from app.schemas.identity import (
    CreateIdentityRequest, CreateIdentityResponse, IdentityResponse, SetPasswordRequest,
)
from app.services import identity_service

identity_router = APIRouter(prefix="/admin/identities", tags=["identity-admin"])


def _require_identity_scope(caller: ServiceAccount = Depends(require_service_account)) -> ServiceAccount:
    """Independent of the SSO scopes on the SAME service account -- a
    service provisioned only to redeem SSO codes must not automatically
    gain the ability to create/deactivate identities, and vice versa (see
    app/models/service_account.py's own docstring)."""
    if not caller.may_manage_identities:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Not permitted to manage identities")
    return caller


@identity_router.post("", response_model=CreateIdentityResponse, status_code=status.HTTP_201_CREATED)
async def create_identity_route(
    body: CreateIdentityRequest,
    caller: ServiceAccount = Depends(_require_identity_scope),
    db: AsyncSession = Depends(get_db),
) -> CreateIdentityResponse:
    try:
        user, temp_password = await identity_service.create_identity(
            db, identifier=body.identifier, password=body.password, username=body.username,
        )
    except identity_service.DuplicateIdentifierError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
    return CreateIdentityResponse(
        id=str(user.id), identifier=user.identifier, username=user.username,
        is_active=user.is_active, temporary_password=temp_password,
    )


@identity_router.get("/{identity_id}", response_model=IdentityResponse)
async def get_identity_route(
    identity_id: uuid.UUID,
    caller: ServiceAccount = Depends(_require_identity_scope),
    db: AsyncSession = Depends(get_db),
) -> IdentityResponse:
    try:
        user = await identity_service.get_identity(db, identity_id)
    except identity_service.IdentityNotFoundError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Identity not found") from exc
    return IdentityResponse(
        id=str(user.id), identifier=user.identifier, username=user.username,
        is_active=user.is_active, created_at=user.created_at,
    )


@identity_router.post("/{identity_id}/activate", status_code=status.HTTP_204_NO_CONTENT)
async def activate_identity_route(
    identity_id: uuid.UUID,
    caller: ServiceAccount = Depends(_require_identity_scope),
    db: AsyncSession = Depends(get_db), redis: Redis = Depends(get_redis),
) -> None:
    try:
        await identity_service.set_active(db, redis, user_id=identity_id, is_active=True)
    except identity_service.IdentityNotFoundError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Identity not found") from exc


@identity_router.post("/{identity_id}/deactivate", status_code=status.HTTP_204_NO_CONTENT)
async def deactivate_identity_route(
    identity_id: uuid.UUID,
    caller: ServiceAccount = Depends(_require_identity_scope),
    db: AsyncSession = Depends(get_db), redis: Redis = Depends(get_redis),
) -> None:
    try:
        await identity_service.set_active(db, redis, user_id=identity_id, is_active=False)
    except identity_service.IdentityNotFoundError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Identity not found") from exc


@identity_router.post("/{identity_id}/set-password", status_code=status.HTTP_204_NO_CONTENT)
async def set_password_route(
    identity_id: uuid.UUID, body: SetPasswordRequest,
    caller: ServiceAccount = Depends(_require_identity_scope),
    db: AsyncSession = Depends(get_db), redis: Redis = Depends(get_redis),
) -> None:
    try:
        await identity_service.admin_set_password(db, redis, user_id=identity_id, new_password=body.new_password)
    except identity_service.IdentityNotFoundError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Identity not found") from exc
    except identity_service.IdentityError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
