#!/usr/bin/env python3
"""Dev-only bootstrap: create one identity directly in the database, with
a real bcrypt hash, so the ACTUAL /auth/login endpoint can be used to
obtain a genuinely-issued token afterward -- this script never mints a
JWT itself.

Usage:
    python scripts/create_dev_user.py <identifier> <password>

Not an API endpoint, not wired into app/main.py, not for production use.
This exists only so Phase 3B's integration test can obtain a real,
login-issued token instead of hand-minting one.

Phase 5 built the real, authenticated, production-facing equivalent:
POST /admin/identities (app/api/identity_routes.py), gated by a service
account's own may_manage_identities scope -- that is the path a real
deployment (or a migration script) should use. This dev script is kept
only because it is zero-dependency (no service account needs to exist
first) and remains convenient for the narrow case of standing up a single
local throwaway stack from nothing.
"""
from __future__ import annotations

import asyncio
import sys
import uuid

from app.core.database import AsyncSessionLocal
from app.core.security import hash_password
from app.models.user import User


async def main(identifier: str, password: str) -> None:
    async with AsyncSessionLocal() as session:
        user = User(id=uuid.uuid4(), identifier=identifier, hashed_password=hash_password(password), is_active=True)
        session.add(user)
        await session.commit()
        print(f"created user id={user.id} identifier={identifier!r}")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("usage: create_dev_user.py <identifier> <password>", file=sys.stderr)
        raise SystemExit(2)
    asyncio.run(main(sys.argv[1], sys.argv[2]))
