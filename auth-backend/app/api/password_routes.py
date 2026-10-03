from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db, get_redis, require_human_user_id
from app.core.config import settings
from app.core.password_reset import PasswordResetUnavailableError
from app.core.rate_limit import RateLimitExceeded, check_rate_limit
from app.schemas.password import ChangePasswordRequest, PasswordResetConfirmRequest, PasswordResetRequest
from app.services import password_service

password_router = APIRouter(prefix="/auth", tags=["password"])


@password_router.post("/change-password", status_code=status.HTTP_204_NO_CONTENT)
async def change_password_route(
    body: ChangePasswordRequest,
    user_id: str = Depends(require_human_user_id),
    db: AsyncSession = Depends(get_db), redis: Redis = Depends(get_redis),
) -> None:
    try:
        await password_service.change_password(
            db, redis, user_id=user_id,
            current_password=body.current_password, new_password=body.new_password,
        )
    except password_service.PasswordError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc


@password_router.post("/password-reset/request", status_code=status.HTTP_202_ACCEPTED)
async def request_password_reset_route(
    body: PasswordResetRequest, request: Request,
    db: AsyncSession = Depends(get_db), redis: Redis = Depends(get_redis),
) -> dict:
    client_ip = request.client.host if request.client else "unknown"
    try:
        await check_rate_limit(redis, f"rate_limit:password-reset:{client_ip}")
    except RateLimitExceeded as exc:
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Too many requests") from exc

    try:
        code = await password_service.request_password_reset(db, redis, identifier=body.identifier)
    except PasswordResetUnavailableError as exc:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Try again shortly") from exc

    # Same response whether or not `identifier` exists -- closes the
    # account-enumeration gap a differing response would open. The reset
    # code itself is returned here ONLY in a non-production environment,
    # since no email/SMS transport exists yet (see
    # docs/PHASE5_BLUMAX_AUTH_CAPABILITY_COMPLETION.md) -- a production
    # deployment must wire a real transport and stop returning this field.
    if not settings.is_production and code is not None:
        return {"detail": "If the identifier exists, a reset code has been issued.", "dev_reset_code": code}
    return {"detail": "If the identifier exists, a reset code has been issued."}


@password_router.post("/password-reset/confirm", status_code=status.HTTP_204_NO_CONTENT)
async def confirm_password_reset_route(
    body: PasswordResetConfirmRequest,
    db: AsyncSession = Depends(get_db), redis: Redis = Depends(get_redis),
) -> None:
    try:
        await password_service.confirm_password_reset(
            db, redis, reset_code=body.reset_code, new_password=body.new_password,
        )
    except password_service.PasswordError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    except PasswordResetUnavailableError as exc:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Try again shortly") from exc
