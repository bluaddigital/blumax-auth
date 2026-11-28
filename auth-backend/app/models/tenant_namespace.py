"""Tenant staff-identity namespace: the minimum Auth needs to resolve a
login's hospital code / tenant slug to the platform tenant UUID BEFORE it
looks up an account (owner decision 2026-11-28).

Not a tenant registry and not a copy of Superadmin's tenant record: it
holds only (tenant_id, slug). It is written by the identity API when a
tenant-scoped account is created with a `tenant_slug` (a Superadmin- or
product-driven call), never by Core's sync, so it adds no Core dependency.
"""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, String, func
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


def normalize_slug(slug: str) -> str:
    return slug.strip().lower()


class TenantNamespace(Base):
    __tablename__ = "tenant_namespaces"

    tenant_id: Mapped[uuid.UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True)
    # Stored normalized (normalize_slug); unique so a slug names one tenant.
    slug: Mapped[str] = mapped_column(String(255), nullable=False, unique=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
