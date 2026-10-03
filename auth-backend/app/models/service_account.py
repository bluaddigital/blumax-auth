"""A service (application) identity -- deliberately NOT a row in `users`.

Core's own service accounts are "shadow" rows in its `users` table because
Core's authorization model (tenant_memberships + role) only knows how to
grant permissions to "a user" -- reusing that machinery was the pragmatic
choice there. Blumax Auth has no tenant/role/permission model at all (by
design: see app/models/user.py), so there is nothing to reuse and no
reason to pretend a service is a user. A ServiceAccount gets its own id
space, entirely separate from human `users.id`, so a service `sub` can
never collide with or be mistaken for a human one even before the token's
`type` claim is checked.

Least-privilege scopes are modeled as explicit, narrow capabilities (never
a single do-everything boolean, and never embedded in the resulting JWT --
see ServiceTokenClaims's own docstring for why):

  destination_app         Which application this account REDEEMS (exchanges)
                           inbound SSO codes for. None = cannot exchange at
                           all. An account can represent exactly one
                           destination, matching one application's own
                           identity (e.g. "labs") -- it can never redeem a
                           code meant for a different application.

  may_mint_on_behalf       Whether this account may vouch for a DIFFERENT
                           user and mint an SSO code for them (used by a
                           source application's own backend, e.g. an app
                           switcher). False by default -- most service
                           accounts only ever need to exchange, never mint.

  allowed_mint_destinations
                           When may_mint_on_behalf is true, the exact set of
                           destination_app values this account may target.
                           Empty/NULL means it may mint for NONE (fail
                           closed, never "any") even if may_mint_on_behalf
                           is true -- both conditions must independently
                           allow a given mint.

  may_manage_identities    Whether this account may call the identity-
                           management API (create/activate/deactivate/
                           set-password on a `users` row). Independent of
                           the SSO scopes above -- an account provisioned
                           only to redeem SSO codes must not automatically
                           gain the ability to create or deactivate
                           identities, and vice versa.
"""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, String, func
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class ServiceAccount(Base):
    __tablename__ = "service_accounts"

    id: Mapped[uuid.UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(100), unique=True, nullable=False, index=True)
    client_id: Mapped[str] = mapped_column(String(100), unique=True, nullable=False, index=True)
    client_secret_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    destination_app: Mapped[str | None] = mapped_column(String(50), nullable=True)
    may_mint_on_behalf: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    allowed_mint_destinations: Mapped[list[str] | None] = mapped_column(ARRAY(String(50)), nullable=True)
    may_manage_identities: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
    last_authenticated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    def can_exchange_for(self, destination_app: str) -> bool:
        return self.is_active and self.destination_app == destination_app

    def can_mint_for(self, destination_app: str) -> bool:
        return (
            self.is_active
            and self.may_mint_on_behalf
            and bool(self.allowed_mint_destinations)
            and destination_app in self.allowed_mint_destinations
        )
