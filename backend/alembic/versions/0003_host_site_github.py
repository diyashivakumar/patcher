"""Site checks table + project source columns (Website Check + GitHub import)

Additive only: a new site_checks table and three nullable columns on projects.
Existing rows and tables are untouched.

Revision ID: 0003_host_site_github
Revises: 0002_gauntlet_forensics
Create Date: 2026-10-31
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0003_host_site_github"
down_revision = "0002_gauntlet_forensics"
branch_labels = None
depends_on = None

JSONB = postgresql.JSONB(astext_type=sa.Text())


def upgrade() -> None:
    op.add_column("projects", sa.Column("source_url", sa.String(2048), nullable=True))
    op.add_column("projects", sa.Column("source_ref", sa.String(255), nullable=True))
    op.add_column("projects", sa.Column("source_commit", sa.String(64), nullable=True))

    op.create_table(
        "site_checks",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("url", sa.String(2048), nullable=False),
        sa.Column("host", sa.String(255), nullable=False),
        sa.Column("authorized", sa.Boolean(), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("final_url", sa.String(2048)),
        sa.Column("resolved_ips", JSONB, nullable=False),
        sa.Column("redirect_chain", JSONB, nullable=False),
        sa.Column("posture", JSONB, nullable=False),
        sa.Column("checks", JSONB, nullable=False),
        sa.Column("error", sa.Text()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_site_checks_host", "site_checks", ["host"])


def downgrade() -> None:
    op.drop_index("ix_site_checks_host", table_name="site_checks")
    op.drop_table("site_checks")
    op.drop_column("projects", "source_commit")
    op.drop_column("projects", "source_ref")
    op.drop_column("projects", "source_url")
