"""Add scan upload tracking

Revision ID: 002
Revises: 001
Create Date: 2026-06-29
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "002"
down_revision: Union[str, None] = "001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "scan_uploads",
        sa.Column("id", sa.dialects.postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "user_id",
            sa.dialects.postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("filename", sa.Text, nullable=False),
        sa.Column("source", sa.String(50), nullable=False),
        sa.Column("uploaded_at", sa.DateTime(timezone=True)),
    )
    op.add_column("findings", sa.Column("upload_id", sa.dialects.postgresql.UUID(as_uuid=True), nullable=True))
    op.create_foreign_key(
        "findings_upload_id_fkey",
        "findings",
        "scan_uploads",
        ["upload_id"],
        ["id"],
        ondelete="SET NULL",
    )


def downgrade() -> None:
    op.drop_constraint("findings_upload_id_fkey", "findings", type_="foreignkey")
    op.drop_column("findings", "upload_id")
    op.drop_table("scan_uploads")
