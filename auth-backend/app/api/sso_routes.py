from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db, get_redis, require_human_user_id, require_service_account
from app.core.sso_code import SsoCodeUnavailableError
from app.models.service_account import ServiceAccount
from app.schemas.sso import (
    SsoCodeRequest, SsoCodeResponse, SsoConsumeRequest, SsoConsumeResponse,
    SsoExchangeRequest, SsoExchangeResponse, SsoMintOnBehalfRequest,
)
from app.services import sso_service

sso_router = APIRouter(prefix="/auth/sso", tags=["sso"])


@sso_router.post("/code", response_model=SsoCodeResponse)
async def mint_code_route(
    body: SsoCodeRequest,
    user_id: str = Depends(require_human_user_id),
    redis: Redis = Depends(get_redis),
) -> SsoCodeResponse:
    try:
        code, expires_in = await sso_service.mint_code_for_self(
            redis, user_id=user_id, destination_app=body.destination_app,
        )
    except SsoCodeUnavailableError as exc:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "SSO temporarily unavailable") from exc
    return SsoCodeResponse(code=code, expires_in=expires_in)


@sso_router.post("/code/on-behalf", response_model=SsoCodeResponse)
async def mint_code_on_behalf_route(
    body: SsoMintOnBehalfRequest,
    caller: ServiceAccount = Depends(require_service_account),
    db: AsyncSession = Depends(get_db),
    redis: Redis = Depends(get_redis),
) -> SsoCodeResponse:
    try:
        code, expires_in = await sso_service.mint_code_on_behalf(
            redis, db, caller=caller, target_user_id=body.user_id, destination_app=body.destination_app,
        )
    except sso_service.SsoError as exc:
        raise HTTPException(status.HTTP_403_FORBIDDEN, str(exc)) from exc
    except SsoCodeUnavailableError as exc:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "SSO temporarily unavailable") from exc
    return SsoCodeResponse(code=code, expires_in=expires_in)


@sso_router.post("/exchange", response_model=SsoExchangeResponse)
async def exchange_route(
    body: SsoExchangeRequest,
    caller: ServiceAccount = Depends(require_service_account),
    db: AsyncSession = Depends(get_db),
    redis: Redis = Depends(get_redis),
) -> SsoExchangeResponse:
    try:
        access_token, expires_in = await sso_service.exchange_code(redis, db, caller=caller, code=body.code)
    except sso_service.SsoError as exc:
        # Every failure mode (unknown code, expired, replayed, wrong
        # destination, wrong application) collapses to the SAME generic
        # 401 -- a caller must not be able to distinguish them.
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or expired code") from exc
    except SsoCodeUnavailableError as exc:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "SSO temporarily unavailable") from exc
    return SsoExchangeResponse(access_token=access_token, expires_in=expires_in)


@sso_router.post("/code/consume", response_model=SsoConsumeResponse)
async def consume_route(
    body: SsoConsumeRequest, db: AsyncSession = Depends(get_db), redis: Redis = Depends(get_redis),
) -> SsoConsumeResponse:
    try:
        access_token, refresh_token = await sso_service.consume_code_public(redis, db, code=body.code)
    except sso_service.SsoError as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or expired code") from exc
    except SsoCodeUnavailableError as exc:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "SSO temporarily unavailable") from exc
    return SsoConsumeResponse(access_token=access_token, refresh_token=refresh_token)
