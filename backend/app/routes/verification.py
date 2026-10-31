import uuid

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database import get_db
from app.errors import ApiError, not_found
from app.models import Patch, Project, RegressionCase, VerificationRun
from app.schemas.verification import RegressionCaseOut, VerificationRunCreate, VerificationRunDetail, VerificationRunOut
from app.serializers import run_out
from app.verification import engine

router = APIRouter(tags=["verification"])


@router.post("/verification/run", response_model=VerificationRunDetail, status_code=201)
def run_verification(body: VerificationRunCreate, db: Session = Depends(get_db)):
    """patch_id -> Proof-of-Fix (before vs after). project_id + scenario -> baseline exploit replay."""
    try:
        if body.patch_id:
            patch = db.get(Patch, body.patch_id)
            if not patch:
                raise not_found("Patch")
            run = engine.run_proof_of_fix(db, patch, db.get(Project, patch.project_id))
        else:
            project = db.get(Project, body.project_id)
            if not project:
                raise not_found("Project")
            run = engine.run_baseline(db, project, body.scenario)
    except engine.VerificationNotPossible as exc:
        raise ApiError(409, "verification_not_possible", str(exc)) from exc
    db.commit()
    db.refresh(run)
    return run_out(run)


@router.get("/verification", response_model=list[VerificationRunOut])
def list_runs(project_id: uuid.UUID | None = None, patch_id: uuid.UUID | None = None,
              kind: str | None = None, db: Session = Depends(get_db)):
    stmt = select(VerificationRun).order_by(VerificationRun.created_at.desc()).limit(100)
    if project_id:
        stmt = stmt.where(VerificationRun.project_id == project_id)
    if patch_id:
        stmt = stmt.where(VerificationRun.patch_id == patch_id)
    if kind:
        stmt = stmt.where(VerificationRun.kind == kind)
    return [VerificationRunOut.model_validate(r) for r in db.scalars(stmt).all()]


@router.get("/verification/{run_id}", response_model=VerificationRunDetail)
def get_run(run_id: uuid.UUID, db: Session = Depends(get_db)):
    run = db.get(VerificationRun, run_id)
    if not run:
        raise not_found("Verification run")
    return run_out(run)


@router.get("/regression-cases", response_model=list[RegressionCaseOut], tags=["gauntlet"])
def list_regression_cases(scenario: str | None = None, db: Session = Depends(get_db)):
    """Confirmed Gauntlet bypasses preserved as reusable tests (replayed on every later verification)."""
    stmt = select(RegressionCase).order_by(RegressionCase.created_at.desc())
    if scenario:
        stmt = stmt.where(RegressionCase.scenario == scenario)
    return [RegressionCaseOut.model_validate(c) for c in db.scalars(stmt).all()]
