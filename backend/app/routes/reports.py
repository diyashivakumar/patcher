import uuid
from typing import Literal

from fastapi import APIRouter, Depends
from fastapi.responses import HTMLResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database import get_db
from app.errors import not_found
from app.models import Project, VerificationRun
from app.reports.generator import build_report, render_html

router = APIRouter(tags=["reports"])


@router.get("/reports")
def list_reports(db: Session = Depends(get_db)):
    """One report per completed verification run (report_id == verification run id)."""
    runs = db.scalars(select(VerificationRun).order_by(VerificationRun.created_at.desc()).limit(100)).all()
    return [
        {"report_id": r.id, "kind": r.kind, "scenario": r.scenario, "status": r.status, "verdict": r.verdict,
         "original_vulnerability_reproduced": r.original_vulnerability_reproduced,
         "project_id": r.project_id, "patch_id": r.patch_id,
         "patch_strategy": r.patch.strategy if r.patch else None, "created_at": r.created_at}
        for r in runs
    ]


@router.get("/reports/{report_id}", responses={200: {"content": {"text/html": {}}}})
def get_report(report_id: uuid.UUID, format: Literal["json", "html"] = "json", db: Session = Depends(get_db)):
    run = db.get(VerificationRun, report_id)
    if not run:
        raise not_found("Report")
    report = build_report(run, db.get(Project, run.project_id))
    if format == "html":
        return HTMLResponse(render_html(report), headers={
            "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'"})
    return report
