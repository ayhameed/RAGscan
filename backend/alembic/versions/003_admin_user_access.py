"""Add user admin and approval controls

Revision ID: 003
Revises: 002
Create Date: 2026-07-07
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "003"
down_revision: Union[str, None] = "002"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("users", sa.Column("is_admin", sa.Boolean(), nullable=False, server_default=sa.text("false")))
    op.add_column("users", sa.Column("is_approved", sa.Boolean(), nullable=False, server_default=sa.text("true")))
    op.add_column("users", sa.Column("is_blocked", sa.Boolean(), nullable=False, server_default=sa.text("false")))
    op.add_column("users", sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("users", sa.Column("blocked_at", sa.DateTime(timezone=True), nullable=True))

    op.execute("UPDATE users SET is_approved = TRUE WHERE is_approved IS DISTINCT FROM TRUE")
    op.execute(
        """
        UPDATE users
        SET is_admin = TRUE,
            is_approved = TRUE,
            approved_at = COALESCE(approved_at, NOW())
        WHERE lower(email) = 'hameedyunusa@outlook.com'
        """
    )


def downgrade() -> None:
    op.drop_column("users", "blocked_at")
    op.drop_column("users", "approved_at")
    op.drop_column("users", "is_blocked")
    op.drop_column("users", "is_approved")
    op.drop_column("users", "is_admin")
