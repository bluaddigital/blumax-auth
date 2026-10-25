"""Keeps tenant_memberships in sync with Core's own user_tenant_memberships,
driven by Core's blumax_auth_tenant_membership_sync_relay.py consuming the
existing TENANT_MEMBER_ROLE_ASSIGNED / TENANT_MEMBER_REVOKED events. See
app/models/tenant_membership.py's own docstring for what this deliberately
does not replicate from Core's full claim-resolution logic.
"""
from __future__ import annotations

import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.tenant_membership import TenantMembership


async def sync_membership_from_core(
    db: AsyncSession,
    *,
    user_id: uuid.UUID,
    tenant_id: uuid.UUID,
    tenant_slug: str | None,
    role_name: str,
    role_archetype: str,
    facility_ids: list[uuid.UUID],
) -> None:
    """Upsert by (user_id, tenant_id) -- a role CHANGE for an existing
    membership (set_member_role) carries the same event type as the first
    assignment (staff creation), both land here as a plain replace, same
    "one event covers both" reasoning TENANT_MEMBER_ROLE_ASSIGNED's own
    docstring in blumax-backend gives."""
    existing = (
        await db.execute(
            select(TenantMembership).where(
                TenantMembership.user_id == user_id, TenantMembership.tenant_id == tenant_id,
            )
        )
    ).scalar_one_or_none()

    if existing is None:
        db.add(TenantMembership(
            user_id=user_id, tenant_id=tenant_id, tenant_slug=tenant_slug,
            role_name=role_name, role_archetype=role_archetype,
            facility_ids=facility_ids, is_active=True,
        ))
    else:
        existing.tenant_slug = tenant_slug
        existing.role_name = role_name
        existing.role_archetype = role_archetype
        existing.facility_ids = facility_ids
        existing.is_active = True
    await db.commit()


async def revoke_membership_from_core(
    db: AsyncSession, *, user_id: uuid.UUID, tenant_id: uuid.UUID,
) -> None:
    """Marks the row inactive rather than deleting it -- login's own tenant
    resolution (see auth_service.login) must treat a revoked membership as
    not-a-choice, the same way an active-row list naturally would, without
    losing the audit trail of "this user once had this role here"."""
    existing = (
        await db.execute(
            select(TenantMembership).where(
                TenantMembership.user_id == user_id, TenantMembership.tenant_id == tenant_id,
            )
        )
    ).scalar_one_or_none()
    if existing is None:
        return
    existing.is_active = False
    await db.commit()
