from fastapi import APIRouter, Depends
from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from app.ai import ollama_service
from app.database import get_db
from app.models import Finding, Patch, Project, Scan, VerificationRun

router = APIRouter(tags=["health"])


@router.get("/health")
def health(db: Session = Depends(get_db)):
    try:
        db.execute(text("SELECT 1"))
        database = "ok"
    except Exception as exc:  # noqa: BLE001 - report, don't crash the health check
        database = f"error: {type(exc).__name__}"
    return {"status": "ok" if database == "ok" else "degraded", "database": database, "version": "0.1.0"}


@router.get("/health/ollama")
def health_ollama():
    return ollama_service.status()


@router.get("/dashboard/summary", tags=["dashboard"])
def dashboard_summary(db: Session = Depends(get_db)):
    """Real counts from the database. Nothing here is estimated or invented."""
    def count(stmt):
        return db.scalar(stmt) or 0

    by_severity = dict(db.execute(select(Finding.severity, func.count()).group_by(Finding.severity)).all())
    by_verdict = dict(db.execute(
        select(VerificationRun.verdict, func.count())
        .where(VerificationRun.kind == "proof_of_fix").group_by(VerificationRun.verdict)
    ).all())
    recent = db.scalars(select(Scan).order_by(Scan.created_at.desc()).limit(8)).all()
    return {
        "total_projects": count(select(func.count()).select_from(Project)),
        "total_scans": count(select(func.count()).select_from(Scan)),
        "total_findings": count(select(func.count()).select_from(Finding)),
        "findings_by_severity": {s: by_severity.get(s, 0) for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW")},
        "patches_generated": count(select(func.count()).select_from(Patch)),
        "patches_verified": count(select(func.count()).select_from(Patch).where(Patch.status == "VERIFIED")),
        "patches_rejected": count(select(func.count()).select_from(Patch).where(Patch.status == "REJECTED")),
        "verification_runs_by_verdict": {v: by_verdict.get(v, 0)
                                         for v in ("VERIFIED", "PARTIALLY_VERIFIED", "FAILED")},
        "recent_scans": [
            {"id": s.id, "project_id": s.project_id, "project_name": s.project.name, "status": s.status,
             "findings_count": s.findings_count, "started_at": s.started_at}
            for s in recent
        ],
    }
