from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db, get_redis
from app.core.database import check_db_connection
from app.core.keys import signing_keys
from app.core.rate_limit import RateLimitExceeded, check_rate_limit
from app.core.security import InvalidToken
from app.schemas.auth import LoginRequest, LogoutRequest, MeResponse, RefreshRequest, TokenResponse
from app.services import auth_service

router = APIRouter(prefix="/auth", tags=["auth"])
health_router = APIRouter(tags=["health"])
jwks_router = APIRouter(tags=["jwks"])
_bearer = HTTPBearer(auto_error=False)


@router.post("/login", response_model=TokenResponse)
async def login_route(
    body: LoginRequest, request: Request,
    db: AsyncSession = Depends(get_db), redis: Redis = Depends(get_redis),
) -> TokenResponse:
    client_ip = request.client.host if request.client else "unknown"
    try:
        await check_rate_limit(redis, f"rate_limit:login:{client_ip}")
    except RateLimitExceeded as exc:
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Too many login attempts") from exc

    try:
        access_token, refresh_token = await auth_service.login(
            db, identifier=body.identifier, password=body.password,
            user_agent=request.headers.get("user-agent"), ip_address=client_ip,
        )
    except auth_service.AuthenticationError as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, str(exc)) from exc

    return TokenResponse(access_token=access_token, refresh_token=refresh_token)


@router.post("/refresh", response_model=TokenResponse)
async def refresh_route(body: RefreshRequest, db: AsyncSession = Depends(get_db)) -> TokenResponse:
    try:
        access_token, refresh_token = await auth_service.refresh(db, refresh_token=body.refresh_token)
    except auth_service.AuthenticationError as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, str(exc)) from exc
    return TokenResponse(access_token=access_token, refresh_token=refresh_token)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout_route(
    body: LogoutRequest, db: AsyncSession = Depends(get_db), redis: Redis = Depends(get_redis),
) -> None:
    await auth_service.logout(
        db, redis, refresh_token=body.refresh_token, all_devices=body.all_devices,
    )


@router.get("/me", response_model=MeResponse)
async def me_route(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
    redis: Redis = Depends(get_redis),
) -> MeResponse:
    if credentials is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Missing bearer token")
    try:
        claims = await auth_service.verify_access_token(redis, credentials.credentials)
    except InvalidToken as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, str(exc)) from exc
    return MeResponse(sub=claims["sub"], iss=claims["iss"], aud=claims["aud"], type=claims["type"])


@jwks_router.get("/.well-known/jwks.json")
async def jwks() -> dict:
    return signing_keys().jwks()


@health_router.get("/health")
async def health(response: Response, redis: Redis = Depends(get_redis)) -> dict:
    """Unlike Core's/Superadmin's own /health (flagged in the prior audit
    for always returning 200 regardless of DB state), this sets a real
    503 when ANY dependency is degraded -- a status-code-only probe can
    tell the difference. Checks all three things this service actually
    needs to function: database, Redis, and a loadable signing key
    (Phase 3C: a missing/unreadable JWT_PRIVATE_KEY in production, or an
    unwritable dev-key path, must not be silently reported as healthy).
    """
    db_ok = await check_db_connection()

    try:
        await redis.ping()
        redis_ok = True
    except Exception:
        redis_ok = False

    try:
        signing_keys()  # cached after first successful load; cheap to call again
        keys_ok = True
    except Exception:
        keys_ok = False

    all_ok = db_ok and redis_ok and keys_ok
    if not all_ok:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return {
        "status": "ok" if all_ok else "degraded",
        "database": "ok" if db_ok else "unreachable",
        "redis": "ok" if redis_ok else "unreachable",
        "signing_key": "ok" if keys_ok else "unavailable",
    }
