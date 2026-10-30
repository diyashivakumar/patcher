"""Initial PatchProof schema

Revision ID: 0001_initial
Revises:
Create Date: 2026-10-30
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0001_initial"
down_revision = None
branch_labels = None
depends_on = None

JSONB = postgresql.JSONB(astext_type=sa.Text())


def _timestamps():
    return [
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    ]


def upgrade() -> None:
    op.create_table(
        "projects",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("description", sa.Text()),
        sa.Column("source_type", sa.String(20), nullable=False),
        sa.Column("fixture_name", sa.String(100)),
        sa.Column("file_count", sa.Integer(), nullable=False),
        sa.Column("total_bytes", sa.BigInteger(), nullable=False),
        *_timestamps(),
    )

    op.create_table(
        "scans",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("project_id", sa.Uuid(), sa.ForeignKey("projects.id", ondelete="CASCADE"), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
        sa.Column("files_scanned", sa.Integer(), nullable=False),
        sa.Column("findings_count", sa.Integer(), nullable=False),
        sa.Column("warnings", JSONB, nullable=False),
        sa.Column("error", sa.Text()),
        *_timestamps(),
    )
    op.create_index("ix_scans_project_id", "scans", ["project_id"])

    op.create_table(
        "findings",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("scan_id", sa.Uuid(), sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False),
        sa.Column("project_id", sa.Uuid(), sa.ForeignKey("projects.id", ondelete="CASCADE"), nullable=False),
        sa.Column("vuln_type", sa.String(20), nullable=False),
        sa.Column("title", sa.String(200), nullable=False),
        sa.Column("severity", sa.String(10), nullable=False),
        sa.Column("severity_rationale", sa.Text(), nullable=False),
        sa.Column("confidence", sa.String(10), nullable=False),
        sa.Column("cwe", sa.String(20), nullable=False),
        sa.Column("file_path", sa.String(500), nullable=False),
        sa.Column("line_start", sa.Integer(), nullable=False),
        sa.Column("line_end", sa.Integer(), nullable=False),
        sa.Column("code_snippet", sa.Text(), nullable=False),
        sa.Column("snippet_start_line", sa.Integer(), nullable=False),
        sa.Column("evidence", JSONB, nullable=False),
        sa.Column("explanation", sa.Text(), nullable=False),
        sa.Column("impact", sa.Text(), nullable=False),
        sa.Column("remediation", sa.Text(), nullable=False),
        sa.Column("detection_method", sa.Text(), nullable=False),
        *_timestamps(),
    )
    op.create_index("ix_findings_scan_id", "findings", ["scan_id"])
    op.create_index("ix_findings_project_id", "findings", ["project_id"])
    op.create_index("ix_findings_severity", "findings", ["severity"])

    op.create_table(
        "patches",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("finding_id", sa.Uuid(), sa.ForeignKey("findings.id", ondelete="CASCADE"), nullable=False),
        sa.Column("project_id", sa.Uuid(), sa.ForeignKey("projects.id", ondelete="CASCADE"), nullable=False),
        sa.Column("strategy", sa.String(50), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("file_path", sa.String(500), nullable=False),
        sa.Column("line_start", sa.Integer(), nullable=False),
        sa.Column("line_end", sa.Integer(), nullable=False),
        sa.Column("original_snippet", sa.Text(), nullable=False),
        sa.Column("patched_snippet", sa.Text(), nullable=False),
        sa.Column("diff", sa.Text(), nullable=False),
        sa.Column("rationale", sa.Text(), nullable=False),
        sa.Column("validation", JSONB, nullable=False),
        sa.Column("approved_by", sa.String(100)),
        sa.Column("approved_at", sa.DateTime(timezone=True)),
        sa.Column("applied_at", sa.DateTime(timezone=True)),
        sa.Column("rolled_back_at", sa.DateTime(timezone=True)),
        sa.Column("backup_path", sa.String(500)),
        *_timestamps(),
    )
    op.create_index("ix_patches_finding_id", "patches", ["finding_id"])
    op.create_index("ix_patches_project_id", "patches", ["project_id"])
    op.create_index("ix_patches_status", "patches", ["status"])

    op.create_table(
        "verification_runs",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("project_id", sa.Uuid(), sa.ForeignKey("projects.id", ondelete="CASCADE"), nullable=False),
        sa.Column("patch_id", sa.Uuid(), sa.ForeignKey("patches.id", ondelete="SET NULL")),
        sa.Column("kind", sa.String(20), nullable=False),
        sa.Column("scenario", sa.String(20), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("verdict", sa.String(30)),
        sa.Column("verdict_reasons", JSONB, nullable=False),
        sa.Column("original_vulnerability_reproduced", sa.Boolean()),
        sa.Column("exploit_blocked_after_patch", sa.Boolean()),
        sa.Column("regressions_pass_after_patch", sa.Boolean()),
        sa.Column("phase_summaries", JSONB, nullable=False),
        sa.Column("raw_output", JSONB),
        sa.Column("error", sa.Text()),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
        sa.Column("duration_ms", sa.Integer()),
        *_timestamps(),
    )
    op.create_index("ix_verification_runs_project_id", "verification_runs", ["project_id"])
    op.create_index("ix_verification_runs_patch_id", "verification_runs", ["patch_id"])
    op.create_index("ix_verification_runs_verdict", "verification_runs", ["verdict"])

    op.create_table(
        "verification_test_results",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("run_id", sa.Uuid(), sa.ForeignKey("verification_runs.id", ondelete="CASCADE"), nullable=False),
        sa.Column("position", sa.Integer(), nullable=False),
        sa.Column("phase", sa.String(20), nullable=False),
        sa.Column("category", sa.String(20), nullable=False),
        sa.Column("test_id", sa.String(100), nullable=False),
        sa.Column("name", sa.String(300), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("status", sa.String(10), nullable=False),
        sa.Column("expected", sa.Text(), nullable=False),
        sa.Column("actual", sa.Text(), nullable=False),
        sa.Column("exploit_succeeded", sa.Boolean()),
        sa.Column("evidence", JSONB, nullable=False),
        sa.Column("privilege_map", JSONB),
        *_timestamps(),
    )
    op.create_index("ix_verification_test_results_run_id", "verification_test_results", ["run_id"])

    op.create_table(
        "audit_logs",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("project_id", sa.Uuid(), sa.ForeignKey("projects.id", ondelete="SET NULL")),
        sa.Column("entity_type", sa.String(30), nullable=False),
        sa.Column("entity_id", sa.Uuid()),
        sa.Column("action", sa.String(50), nullable=False),
        sa.Column("actor", sa.String(100), nullable=False),
        sa.Column("details", JSONB, nullable=False),
        *_timestamps(),
    )
    op.create_index("ix_audit_logs_project_id", "audit_logs", ["project_id"])


def downgrade() -> None:
    for table in ("audit_logs", "verification_test_results", "verification_runs", "patches",
                  "findings", "scans", "projects"):
        op.drop_table(table)
