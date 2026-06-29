"""Initial schema

Revision ID: 001
Revises:
Create Date: 2026-06-29
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from pgvector.sqlalchemy import Vector

revision: str = "001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute("CREATE EXTENSION IF NOT EXISTS vector")
    op.create_table(
        "users",
        sa.Column("id", sa.dialects.postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("email", sa.String(255), unique=True, nullable=False),
        sa.Column("role", sa.String(50), server_default="analyst"),
        sa.Column("pw_hash", sa.Text, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True)),
    )
    op.create_table(
        "findings",
        sa.Column("id", sa.dialects.postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("source", sa.String(50), nullable=False),
        sa.Column("cve_id", sa.String(30)),
        sa.Column("cwe_id", sa.String(30)),
        sa.Column("plugin_id", sa.String(100)),
        sa.Column("title", sa.Text, nullable=False),
        sa.Column("description", sa.Text),
        sa.Column("solution", sa.Text),
        sa.Column("severity_label", sa.String(20), nullable=False),
        sa.Column("cvss3_score", sa.Float),
        sa.Column("epss_score", sa.Float),
        sa.Column("epss_percentile", sa.Float),
        sa.Column("cisa_kev", sa.Boolean, server_default="false"),
        sa.Column("risk_score", sa.Float),
        sa.Column("host_ip", sa.String(50)),
        sa.Column("hostname", sa.String(255)),
        sa.Column("port", sa.Integer),
        sa.Column("protocol", sa.String(10)),
        sa.Column("enriched_at", sa.DateTime(timezone=True)),
        sa.Column("ingested_at", sa.DateTime(timezone=True)),
        sa.Column("raw_data", sa.JSON),
    )
    op.create_table(
        "finding_embeddings",
        sa.Column("finding_id", sa.dialects.postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("findings.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("embedding", Vector(1536)),
    )
    op.create_index(
        "idx_finding_embeddings_ivfflat", "finding_embeddings",
        ["embedding"], postgresql_using="ivfflat",
        postgresql_with={"lists": 100},
        postgresql_ops={"embedding": "vector_cosine_ops"},
    )
    op.create_table(
        "enrichment_cache",
        sa.Column("cve_id", sa.String(30), primary_key=True),
        sa.Column("nvd_data", sa.JSON),
        sa.Column("epss_score", sa.Float),
        sa.Column("epss_percentile", sa.Float),
        sa.Column("cisa_kev", sa.Boolean, server_default="false"),
        sa.Column("cached_at", sa.DateTime(timezone=True)),
    )
    op.create_table(
        "nist_mappings",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("cwe_id", sa.String(30), nullable=False),
        sa.Column("framework", sa.String(20), nullable=False),
        sa.Column("control_family", sa.String(10), nullable=False),
        sa.Column("control_id", sa.String(30), nullable=False),
        sa.Column("description", sa.Text, nullable=False),
        sa.UniqueConstraint("cwe_id", "control_id"),
    )
    op.create_table(
        "compliance_gaps",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("finding_id", sa.dialects.postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("findings.id", ondelete="CASCADE")),
        sa.Column("framework", sa.String(20), nullable=False),
        sa.Column("control_id", sa.String(30), nullable=False),
        sa.Column("gap_level", sa.String(20), nullable=False),
    )
    op.create_table(
        "reports",
        sa.Column("id", sa.dialects.postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("report_type", sa.String(50), nullable=False),
        sa.Column("path", sa.Text, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True)),
    )
    op.create_table(
        "sessions",
        sa.Column("id", sa.dialects.postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("user_id", sa.dialects.postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("users.id", ondelete="CASCADE")),
        sa.Column("history", sa.JSON),
        sa.Column("created_at", sa.DateTime(timezone=True)),
    )
    op.create_table(
        "audit_log",
        sa.Column("id", sa.dialects.postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("user_id", sa.dialects.postgresql.UUID(as_uuid=True)),
        sa.Column("action", sa.String(100), nullable=False),
        sa.Column("entity", sa.String(100), nullable=False),
        sa.Column("ts", sa.DateTime(timezone=True)),
    )


def downgrade() -> None:
    for table in ["audit_log", "sessions", "reports", "compliance_gaps",
                  "nist_mappings", "enrichment_cache", "finding_embeddings",
                  "findings", "users"]:
        op.drop_table(table)
