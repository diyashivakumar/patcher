import uuid

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.challenge import chain_impact
from app.database import get_db
from app.errors import ApiError, not_found
from app.models import Project
from app.schemas.challenge import ChainImpactRequest, ChainImpactResult
from app.verification import adapter

router = APIRouter(tags=["challenge"])


@router.post("/challenge/chain-impact", response_model=ChainImpactResult, status_code=201)
def chain_impact_run(body: ChainImpactRequest | None = None, db: Session = Depends(get_db)):
    """Run the SQLi -> stolen token -> IDOR chain against original / sqli-fixed / idor-fixed / both.

    Uses the existing patch generator for the fixed copies and the existing runner sandbox.
    Synthetic data only; verdict logic and the Proof-of-Fix flow are not involved.
    """
    project = None
    project_id = body.project_id if body else None
    if project_id is not None:
        project = db.get(Project, uuid.UUID(str(project_id)))
        if not project:
            raise not_found("Project")
    try:
        return chain_impact.run_chain_impact(project)
    except chain_impact.ChainImpactError as exc:
        raise ApiError(409, "chain_impact_not_possible", str(exc)) from exc
    except adapter.RunnerError as exc:
        raise ApiError(502, "runner_error", f"The attack-chain runner failed: {exc}") from exc
