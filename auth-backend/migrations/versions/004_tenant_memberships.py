"""Add tenant_memberships -- claim-shaping data only (tenant_id, role
name/archetype, facility scope), a one-way mirror of Core's own
user_tenant_memberships/user_facility_memberships, kept current by Core's
blumax_auth_tenant_membership_sync_relay.py. See
app/models/tenant_membership.py's own docstring for the full reasoning and
what this deliberately does NOT replicate from Core's claim resolution.

Revision ID: 004_tenant_memberships
Revises: 003_username
Create Date: 2026-10-25

"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "004_tenant_memberships"
down_revision = "003_username"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "tenant_memberships",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "user_id", postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False,
        ),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("tenant_slug", sa.String(255), nullable=True),
        sa.Column("role_name", sa.String(255), nullable=False),
        sa.Column("role_archetype", sa.String(50), nullable=False, server_default="VIEWER"),
        sa.Column(
            "facility_ids", postgresql.ARRAY(postgresql.UUID(as_uuid=True)),
            nullable=False, server_default="{}",
        ),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("user_id", "tenant_id", name="uq_tenant_memberships_user_tenant"),
    )
    op.create_index("ix_tenant_memberships_user_id", "tenant_memberships", ["user_id"])
    op.create_index("ix_tenant_memberships_tenant_id", "tenant_memberships", ["tenant_id"])


def downgrade() -> None:
    op.drop_index("ix_tenant_memberships_tenant_id", table_name="tenant_memberships")
    op.drop_index("ix_tenant_memberships_user_id", table_name="tenant_memberships")
    op.drop_table("tenant_memberships")
