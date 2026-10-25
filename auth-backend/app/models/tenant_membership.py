"""Tenant-membership claim-shaping data (2026-10-25, user-approved reversal
of the Phase 1 "no business data in Auth" default -- see MIGRATION.md's
"token scope" decision and PHASE5_BLUMAX_AUTH_CAPABILITY_COMPLETION.md's
"no tenant/role/facility claim, per explicit instruction").

This is NOT an authorization store: it carries only what a token's claims
need to say (tenant_id, tenant_slug, role name/archetype, facility scope),
mirrored one-way from Core's own `user_tenant_memberships` /
`user_facility_memberships`. Core remains the single source of truth for
WHO holds WHICH role and what that role can do -- this table only answers
"what should this user's next token for this tenant say", the same
question Core's own AuthService._resolve_claims answers at login time.

Scoped down from Core's full claim-resolution logic (see that method's own
docstring for everything this simplifies away):
  - No multi-role stacking (TENANT_MEMBER_ADDITIONAL_ROLE_GRANTED/REVOKED)
    -- only the primary membership's role/archetype.
  - No platform-admin-binds-to-an-unlisted-tenant path -- Blumax Auth has
    no is_platform_admin concept yet (Phase 1's User model has none).
  - facility_ids is never NULL ("unrestricted") here -- Core's own
    tenant_admin_unscoped_by_default special case is Core-only complexity
    this table does not replicate. An empty list is the fail-safe default
    (most restrictive), not Core's "no rows means unrestricted" reading.
"""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, String, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class TenantMembership(Base):
    __tablename__ = "tenant_memberships"
    __table_args__ = (
        UniqueConstraint("user_id", "tenant_id", name="uq_tenant_memberships_user_tenant"),
    )

    id: Mapped[uuid.UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True,
    )
    tenant_id: Mapped[uuid.UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False, index=True)
    tenant_slug: Mapped[str | None] = mapped_column(String(255), nullable=True)
    role_name: Mapped[str] = mapped_column(String(255), nullable=False)
    role_archetype: Mapped[str] = mapped_column(String(50), nullable=False, default="VIEWER")
    # Never NULL -- see module docstring. Empty = no facility access granted
    # yet, same fail-safe-closed posture as Core's own membership rows
    # before any facility is explicitly added.
    facility_ids: Mapped[list[uuid.UUID]] = mapped_column(
        ARRAY(PGUUID(as_uuid=True)), nullable=False, default=list,
    )
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
