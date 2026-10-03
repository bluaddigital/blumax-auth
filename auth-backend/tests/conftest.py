from __future__ import annotations

import uuid

import pytest_asyncio
import redis.asyncio as aioredis
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_redis
from app.core.config import settings
from app.core.database import Base, engine
from app.core.security import hash_password
from app.main import app
from app.models.service_account import ServiceAccount
from app.models.user import User


@pytest_asyncio.fixture(autouse=True)
async def _fresh_redis_per_test():
    """A module-level cached Redis client (app.api.deps.get_redis's
    singleton) outlives any one test's event loop under pytest-asyncio's
    default function-scoped loop, causing 'Event loop is closed' on the
    next test. Give every test its own client via a dependency override,
    and flush it so rate-limit/session state never leaks between tests.
    """
    client = aioredis.from_url(settings.REDIS_URL, decode_responses=True)
    await client.flushdb()
    app.dependency_overrides[get_redis] = lambda: client
    yield client
    app.dependency_overrides.pop(get_redis, None)
    await client.aclose()


@pytest_asyncio.fixture(autouse=True)
async def _reset_schema():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    yield


@pytest_asyncio.fixture
async def db_session():
    from app.core.database import AsyncSessionLocal
    async with AsyncSessionLocal() as session:
        yield session


@pytest_asyncio.fixture
async def test_user(db_session: AsyncSession) -> User:
    user = User(
        id=uuid.uuid4(), identifier="alice@example.test",
        hashed_password=hash_password("correct-horse-battery-staple"),
        is_active=True,
    )
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)
    return user


@pytest_asyncio.fixture
async def client():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


async def _make_service_account(db_session: AsyncSession, **overrides) -> tuple[ServiceAccount, str]:
    """Returns (account, plaintext_client_secret). The plaintext secret is
    generated fresh per call -- never a fixed test constant -- and
    returned once, matching real provisioning's own one-time-display
    convention."""
    plaintext_secret = f"secret-{uuid.uuid4().hex}"
    account = ServiceAccount(
        id=uuid.uuid4(),
        name=overrides.pop("name", f"test-service-{uuid.uuid4().hex[:8]}"),
        client_id=f"client-{uuid.uuid4().hex}",
        client_secret_hash=hash_password(plaintext_secret),
        is_active=overrides.pop("is_active", True),
        destination_app=overrides.pop("destination_app", None),
        may_mint_on_behalf=overrides.pop("may_mint_on_behalf", False),
        allowed_mint_destinations=overrides.pop("allowed_mint_destinations", None),
        may_manage_identities=overrides.pop("may_manage_identities", False),
    )
    db_session.add(account)
    await db_session.commit()
    await db_session.refresh(account)
    return account, plaintext_secret


@pytest_asyncio.fixture
async def make_service_account(db_session: AsyncSession):
    """Factory fixture: `account, secret = await make_service_account(destination_app="labs")`."""

    async def _factory(**overrides) -> tuple[ServiceAccount, str]:
        return await _make_service_account(db_session, **overrides)

    return _factory
