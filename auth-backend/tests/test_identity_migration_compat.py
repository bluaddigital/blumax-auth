"""Proves, in executable code (not just documentation), the Phase 4A
identity-migration recommendation: Core user UUIDs can be preserved as
Blumax Auth `users.id` values, and an existing bcrypt hash produced by a
DIFFERENT library (raw `bcrypt`, the way Labs/Core hash passwords) verifies
through Blumax Auth's passlib-based verifier with ZERO conversion.
"""
from __future__ import annotations

import uuid

import bcrypt
import pytest
from sqlalchemy import select

from app.core.security import hash_password, verify_password, verify_password_constant_time
from app.models.user import User
from app.services.identity_service import DuplicateIdentifierError, create_identity_with_id


async def test_preserved_uuid_insert_round_trips(db_session):
    """An explicitly-chosen id (standing in for an existing Core users.id)
    is accepted, stored, and retrievable unchanged -- no server-side
    default fights it, no CHECK constraint rejects it (see
    migrations/versions/001_initial.py: only a PK and a unique index on
    identifier, nothing else)."""
    preserved_id = uuid.uuid4()  # stands in for an existing Core users.id
    user = await create_identity_with_id(
        db_session, user_id=preserved_id, identifier="migrated-user@example.test",
        hashed_password=hash_password("whatever"), is_active=True,
    )
    assert user.id == preserved_id

    row = (await db_session.execute(select(User).where(User.id == preserved_id))).scalar_one()
    assert row.id == preserved_id
    assert row.identifier == "migrated-user@example.test"


async def test_preserved_uuid_duplicate_identifier_rejected(db_session):
    await create_identity_with_id(
        db_session, user_id=uuid.uuid4(), identifier="dup@example.test",
        hashed_password=hash_password("x"), is_active=True,
    )
    with pytest.raises(DuplicateIdentifierError):
        await create_identity_with_id(
            db_session, user_id=uuid.uuid4(), identifier="dup@example.test",
            hashed_password=hash_password("y"), is_active=True,
        )


def test_hash_produced_by_raw_bcrypt_library_verifies_through_passlib():
    """Labs (and Core) hash passwords with the raw `bcrypt` library
    directly (bcrypt.hashpw/checkpw), not passlib. This proves that exact
    hash format verifies, byte-for-byte, through Blumax Auth's
    passlib-based verify_password with no conversion step -- the concrete
    evidence behind the Phase 4A report's compatibility claim, not just
    the claim itself."""
    raw_bcrypt_hash = bcrypt.hashpw(b"a-core-or-labs-password", bcrypt.gensalt()).decode("ascii")
    assert verify_password("a-core-or-labs-password", raw_bcrypt_hash)
    assert not verify_password("wrong-password", raw_bcrypt_hash)


def test_hash_produced_by_raw_bcrypt_library_verifies_constant_time_path_too():
    raw_bcrypt_hash = bcrypt.hashpw(b"another-password", bcrypt.gensalt()).decode("ascii")
    assert verify_password_constant_time("another-password", raw_bcrypt_hash)


def test_blumax_auth_hash_also_verifies_the_other_direction():
    """And the reverse, for completeness: a hash Blumax Auth itself
    produces verifies against raw bcrypt.checkpw too -- confirming the two
    libraries are genuinely interoperable, not just one-way compatible."""
    blumax_auth_hash = hash_password("some-password")
    assert bcrypt.checkpw(b"some-password", blumax_auth_hash.encode("ascii"))
