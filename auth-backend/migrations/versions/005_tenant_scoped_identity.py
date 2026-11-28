"""Tenant-scoped staff identity (owner decision 2026-11-28: "One tenant =
one customer hospital organization = its own staff identity namespace").

Adds users.tenant_id (NULL = global legacy row) and
users.username_normalized, and the tenant_namespaces table (tenant_id <->
login slug). Replaces the two GLOBAL unique indexes with partial ones:

  before                              after
  ix_users_identifier UNIQUE          uq_users_identifier_global UNIQUE (identifier) WHERE tenant_id IS NULL
                                      uq_users_tenant_identifier UNIQUE (tenant_id, identifier) WHERE tenant_id IS NOT NULL
                                      ix_users_identifier (non-unique, lookup)
  ix_users_username UNIQUE            uq_users_username_global UNIQUE (username) WHERE tenant_id IS NULL
                                      uq_users_tenant_username UNIQUE (tenant_id, username_normalized)
                                          WHERE tenant_id IS NOT NULL AND username_normalized IS NOT NULL
                                      ix_users_username (non-unique, lookup)

Order matters: the new partial unique indexes are created BEFORE the old
global ones are dropped, so there is no moment without a uniqueness guard.
Every existing row has tenant_id IS NULL after this migration, so the
partial "global" indexes are exactly equivalent to the old ones -- the
migration changes no behaviour until a tenant-scoped row is written (only
possible with TENANT_SCOPED_IDENTITY_MODE=on).

Plain CREATE INDEX (not CONCURRENTLY): the auth users table is small
(staff accounts only). Needs owner approval before it is applied to any
shared database.

Downgrade refuses to run while any tenant-scoped row exists -- restoring
global uniqueness would either fail or force merging two tenants'
accounts, which the decision forbids.

Revision ID: 005_tenant_scoped_identity
Revises: 004_tenant_memberships
Create Date: 2026-11-28

"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "005_tenant_scoped_identity"
down_revision = "004_tenant_memberships"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("users", sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=True))
    op.add_column("users", sa.Column("username_normalized", sa.String(255), nullable=True))
    op.execute(
        "UPDATE users SET username_normalized = NULLIF(lower(btrim(username)), '') "
        "WHERE username IS NOT NULL"
    )
    op.create_index("ix_users_tenant_id", "users", ["tenant_id"])

    # New guards first ...
    op.create_index(
        "uq_users_identifier_global", "users", ["identifier"], unique=True,
        postgresql_where=sa.text("tenant_id IS NULL"),
    )
    op.create_index(
        "uq_users_username_global", "users", ["username"], unique=True,
        postgresql_where=sa.text("tenant_id IS NULL"),
    )
    op.create_index(
        "uq_users_tenant_identifier", "users", ["tenant_id", "identifier"], unique=True,
        postgresql_where=sa.text("tenant_id IS NOT NULL"),
    )
    op.create_index(
        "uq_users_tenant_username", "users", ["tenant_id", "username_normalized"], unique=True,
        postgresql_where=sa.text("tenant_id IS NOT NULL AND username_normalized IS NOT NULL"),
    )
    # ... then swap the old global unique indexes for plain lookup indexes.
    op.drop_index("ix_users_identifier", table_name="users")
    op.create_index("ix_users_identifier", "users", ["identifier"])
    op.drop_index("ix_users_username", table_name="users")
    op.create_index("ix_users_username", "users", ["username"])

    op.create_table(
        "tenant_namespaces",
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("slug", sa.String(255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_tenant_namespaces_slug", "tenant_namespaces", ["slug"], unique=True)


def downgrade() -> None:
    bind = op.get_bind()
    scoped = bind.execute(sa.text("SELECT count(*) FROM users WHERE tenant_id IS NOT NULL")).scalar()
    if scoped:
        raise RuntimeError(
            f"refusing to downgrade: {scoped} tenant-scoped user row(s) exist; global uniqueness "
            "cannot be restored without merging separate tenants' accounts"
        )
    op.drop_index("ix_tenant_namespaces_slug", table_name="tenant_namespaces")
    op.drop_table("tenant_namespaces")

    op.drop_index("ix_users_username", table_name="users")
    op.create_index("ix_users_username", "users", ["username"], unique=True)
    op.drop_index("ix_users_identifier", table_name="users")
    op.create_index("ix_users_identifier", "users", ["identifier"], unique=True)
    op.drop_index("uq_users_tenant_username", table_name="users")
    op.drop_index("uq_users_tenant_identifier", table_name="users")
    op.drop_index("uq_users_username_global", table_name="users")
    op.drop_index("uq_users_identifier_global", table_name="users")
    op.drop_index("ix_users_tenant_id", table_name="users")
    op.drop_column("users", "username_normalized")
    op.drop_column("users", "tenant_id")
