"""Exploit Variant Gauntlet + Data Exposure Forensics

Additive only: two nullable JSONB columns on verification_runs and a new regression_cases table.
Existing rows are untouched (old runs simply have NULL gauntlet/forensics).

Revision ID: 0002_gauntlet_forensics
Revises: 0001_initial
Create Date: 2026-10-30
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0002_gauntlet_forensics"
down_revision = "0001_initial"
branch_labels = None
depends_on = None

JSONB = postgresql.JSONB(astext_type=sa.Text())


def upgrade() -> None:
    op.add_column("verification_runs", sa.Column("gauntlet", JSONB, nullable=True))
    op.add_column("verification_runs", sa.Column("forensics", JSONB, nullable=True))

    op.create_table(
        "regression_cases",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("fixture_name", sa.String(100), nullable=False),
        sa.Column("scenario", sa.String(20), nullable=False),
        sa.Column("fingerprint", sa.String(32), nullable=False),
        sa.Column("kind", sa.String(20), nullable=False),
        sa.Column("variation", sa.String(200), nullable=False),
        sa.Column("description", sa.String(500), nullable=False),
        sa.Column("input", JSONB, nullable=False),
        sa.Column("check", JSONB),
        sa.Column("source_variant_id", sa.String(100), nullable=False),
        sa.Column("source_run_id", sa.Uuid(), sa.ForeignKey("verification_runs.id", ondelete="SET NULL")),
        sa.Column("source_patch_id", sa.Uuid(), sa.ForeignKey("patches.id", ondelete="SET NULL")),
        sa.Column("original_outcome", JSONB, nullable=False),
        sa.Column("patched_outcome", JSONB, nullable=False),
        sa.Column("times_seen", sa.Integer(), nullable=False),
        sa.Column("last_seen_run_id", sa.Uuid(), sa.ForeignKey("verification_runs.id", ondelete="SET NULL")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("fixture_name", "scenario", "fingerprint", name="uq_regression_case_input"),
    )
    op.create_index("ix_regression_cases_scenario", "regression_cases", ["scenario"])


def downgrade() -> None:
    op.drop_index("ix_regression_cases_scenario", table_name="regression_cases")
    op.drop_table("regression_cases")
    op.drop_column("verification_runs", "forensics")
    op.drop_column("verification_runs", "gauntlet")
