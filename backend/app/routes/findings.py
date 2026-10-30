import uuid

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.ai import ollama_service
from app.database import get_db
from app.errors import not_found
from app.models import Finding, Project
from app.schemas.finding import AIExplanation, FindingDetail
from app.serializers import finding_out

router = APIRouter(tags=["findings"])


def _get(db, finding_id):
    finding = db.get(Finding, finding_id)
    if not finding:
        raise not_found("Finding")
    return finding


@router.get("/findings/{finding_id}", response_model=FindingDetail)
def get_finding(finding_id: uuid.UUID, db: Session = Depends(get_db)):
    finding = _get(db, finding_id)
    return finding_out(finding, db.get(Project, finding.project_id))


@router.post("/findings/{finding_id}/ai-explanation", response_model=AIExplanation)
def ai_explanation(finding_id: uuid.UUID, db: Session = Depends(get_db)):
    """Optional, advisory-only explanation from local Ollama. Always 200; check `available`."""
    return ollama_service.explain_finding(_get(db, finding_id))
