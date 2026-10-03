from __future__ import annotations

from datetime import UTC, datetime

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.security import create_service_token, verify_password_constant_time
from app.models.service_account import ServiceAccount

logger = structlog.get_logger(__name__)


class ServiceAuthenticationError(Exception):
    pass


async def issue_service_token(db: AsyncSession, *, client_id: str, client_secret: str) -> tuple[str, int]:
    result = await db.execute(select(ServiceAccount).where(ServiceAccount.client_id == client_id))
    account = result.scalar_one_or_none()

    # Constant-work check regardless of whether `account` exists -- same
    # timing-side-channel closure as the human login path.
    secret_ok = verify_password_constant_time(
        client_secret, account.client_secret_hash if account is not None else None
    )

    if account is None or not secret_ok:
        logger.info("service_token.failed", client_id=client_id, reason="invalid_credentials")
        raise ServiceAuthenticationError("Invalid credentials")

    if not account.is_active:
        logger.info("service_token.failed", client_id=client_id, reason="inactive")
        raise ServiceAuthenticationError("Service account is deactivated")

    token, _ = create_service_token(service_account_id=account.id, name=account.name)
    account.last_authenticated_at = datetime.now(UTC)
    await db.commit()

    logger.info("service_token.success", service=account.name)
    return token, settings.SERVICE_TOKEN_EXPIRE_MINUTES * 60
