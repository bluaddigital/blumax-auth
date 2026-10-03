from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db, get_redis
from app.core.rate_limit import RateLimitExceeded, check_rate_limit
from app.schemas.service_account import ServiceTokenRequest, ServiceTokenResponse
from app.services import service_account_service

service_router = APIRouter(prefix="/auth", tags=["service"])


@service_router.post("/service-token", response_model=ServiceTokenResponse)
async def service_token_route(
    body: ServiceTokenRequest, request: Request,
    db: AsyncSession = Depends(get_db), redis: Redis = Depends(get_redis),
) -> ServiceTokenResponse:
    client_ip = request.client.host if request.client else "unknown"
    try:
        await check_rate_limit(redis, f"rate_limit:service-token:{client_ip}")
    except RateLimitExceeded as exc:
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Too many requests") from exc

    try:
        token, expires_in = await service_account_service.issue_service_token(
            db, client_id=body.client_id, client_secret=body.client_secret,
        )
    except service_account_service.ServiceAuthenticationError as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, str(exc)) from exc
    return ServiceTokenResponse(access_token=token, expires_in=expires_in)
