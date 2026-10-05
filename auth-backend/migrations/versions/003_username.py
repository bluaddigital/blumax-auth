"""Add username as a second, optional login identifier alongside `identifier`
(email). Core has always supported login by either email or username
(app/modules/identity/infrastructure/repository.py::get_by_identifier); this
single-`identifier` schema only ever carried email, silently dropping
username-login for any account migrated from Core. Nullable + a unique
index (Postgres unique indexes permit multiple NULLs) so existing rows with
no known username are unaffected.

Revision ID: 003_username
Revises: 002_service_accounts
Create Date: 2026-10-05

"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "003_username"
down_revision = "002_service_accounts"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("users", sa.Column("username", sa.String(255), nullable=True))
    op.create_index("ix_users_username", "users", ["username"], unique=True)


def downgrade() -> None:
    op.drop_index("ix_users_username", table_name="users")
    op.drop_column("users", "username")
