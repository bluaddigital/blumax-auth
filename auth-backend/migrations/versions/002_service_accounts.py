"""Service accounts (Phase 5: service-to-service authentication).

Revision ID: 002_service_accounts
Revises: 001_initial
Create Date: 2026-10-02

"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "002_service_accounts"
down_revision = "001_initial"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "service_accounts",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(100), nullable=False),
        sa.Column("client_id", sa.String(100), nullable=False),
        sa.Column("client_secret_hash", sa.String(255), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("destination_app", sa.String(50), nullable=True),
        sa.Column("may_mint_on_behalf", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("allowed_mint_destinations", postgresql.ARRAY(sa.String(50)), nullable=True),
        sa.Column("may_manage_identities", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("last_authenticated_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_service_accounts_name", "service_accounts", ["name"], unique=True)
    op.create_index("ix_service_accounts_client_id", "service_accounts", ["client_id"], unique=True)


def downgrade() -> None:
    op.drop_index("ix_service_accounts_client_id", table_name="service_accounts")
    op.drop_index("ix_service_accounts_name", table_name="service_accounts")
    op.drop_table("service_accounts")
