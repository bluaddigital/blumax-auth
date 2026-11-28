"""The identity record. Deliberately minimal -- see ARCHITECTURE.md: this
table answers "who is this user" only. No role, no organization, no
facility -- those stay in each application's own database, keyed by this
row's `id` (the `sub` claim), exactly like Core's existing `core_user_id`
reference pattern already used by Pharmacy/Labs.

Tenant-scoped staff identity (owner decision 2026-11-28, architecture
master decision 6): "One tenant = one customer hospital organization = its
own staff identity namespace." A row is one of two kinds:

  - GLOBAL (legacy): tenant_id IS NULL. Every row that existed before this
    change (mirrored from Core or created through the identity API). Its
    `identifier` and `username` stay globally unique, exactly as before.
  - TENANT-SCOPED: tenant_id IS NOT NULL. The account exists only inside
    that tenant. Uniqueness is (tenant_id, identifier) and
    (tenant_id, username_normalized) -- the same username or email in
    another tenant is a DIFFERENT account with its own id, password and
    sessions, never linked automatically (not by email, username or
    phone). Login must name the tenant before the account is resolved.

`tenant_id` is the platform tenant UUID (the cross-service contract field);
it is not a membership -- what the account may do in each product is owned
by that product, not by Auth.
"""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Index, String, func, text
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


def normalize_username(username: str | None) -> str | None:
    """Trim + lowercase -- the same policy login has always applied to
    `username` (case-insensitive match) and user_sync applies to
    `identifier`. None/blank -> None."""
    if username is None:
        return None
    value = username.strip().lower()
    return value or None


def normalize_identifier(identifier: str) -> str:
    return identifier.strip().lower()


class User(Base):
    __tablename__ = "users"
    __table_args__ = (
        # Global (legacy) rows keep today's global uniqueness, now expressed
        # as partial indexes so tenant-scoped rows are outside them. While
        # every row has tenant_id IS NULL these are exactly equivalent to the
        # old ix_users_identifier / ix_users_username unique indexes.
        Index(
            "uq_users_identifier_global", "identifier", unique=True,
            postgresql_where=text("tenant_id IS NULL"),
        ),
        Index(
            "uq_users_username_global", "username", unique=True,
            postgresql_where=text("tenant_id IS NULL"),
        ),
        # Tenant-scoped rows: unique per tenant only.
        Index(
            "uq_users_tenant_identifier", "tenant_id", "identifier", unique=True,
            postgresql_where=text("tenant_id IS NOT NULL"),
        ),
        Index(
            "uq_users_tenant_username", "tenant_id", "username_normalized", unique=True,
            postgresql_where=text("tenant_id IS NOT NULL AND username_normalized IS NOT NULL"),
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    # NULL = global legacy account; set = account belongs to exactly this
    # tenant's staff identity namespace (see module docstring).
    tenant_id: Mapped[uuid.UUID | None] = mapped_column(PGUUID(as_uuid=True), nullable=True, index=True)
    identifier: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    # Second, optional login identifier (Core's own `username` column) --
    # see migrations/versions/003_username.py for why `identifier` alone
    # isn't enough. Nullable: not every identity has a known username.
    username: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    # normalize_username(username) -- the per-tenant uniqueness key.
    username_normalized: Mapped[str | None] = mapped_column(String(255), nullable=True)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    @property
    def is_tenant_scoped(self) -> bool:
        return self.tenant_id is not None
