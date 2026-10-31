"""Fix Court API endpoints."""
import uuid
from collections.abc import Iterator
from typing import Any, Optional
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.challenge.schemas import ChallengeOut, ChallengeRunRequest, CandidateOut, JudgeSubmitRequest
from app.challenge.service import (
    get_candidate,
    get_challenge,
    run_challenge_trial,
    submit_judge_replacement,
)
from app.database import get_db, get_engine, _SessionLocal
from app.models.finding import Finding

router = APIRouter(prefix="/challenge", tags=["Fix Court"])


def get_optional_db() -> Iterator[Optional[Session]]:
    """Yield a database session if configured, or None for fixture-only mode."""
    try:
        get_engine()
        if _SessionLocal:
            db = _SessionLocal()
            try:
                yield db
            finally:
                db.close()
            return
    except Exception:
        pass
    yield None


@router.get("/findings")
def list_court_findings(db: Optional[Session] = Depends(get_optional_db)) -> list[dict[str, Any]]:
    """List findings ready to be put on trial in Fix Court."""
    results = []
    if db is not None:
        try:
            findings = db.query(Finding).all()
            for f in findings:
                results.append({
                    "id": str(f.id),
                    "project_id": str(f.project_id),
                    "vuln_type": f.vuln_type,
                    "title": f.title,
                    "severity": f.severity,
                    "file_path": f.file_path,
                    "line_start": f.line_start,
                    "line_end": f.line_end,
                    "target_function": "search" if f.vuln_type == "sqli" else "get_document",
                })
        except Exception:
            pass

    # Provide fixture app vulnerabilities ready for trial
    if not results:
        results = [
            {
                "id": "11111111-1111-1111-1111-111111111111",
                "project_id": "00000000-0000-0000-0000-000000000001",
                "vuln_type": "sqli",
                "title": "SQL Injection in /search (f-string query concatenation)",
                "severity": "CRITICAL",
                "file_path": "fixtures/vulnerable_app/app.py",
                "line_start": 65,
                "line_end": 70,
                "target_function": "search",
            },
            {
                "id": "22222222-2222-2222-2222-222222222222",
                "project_id": "00000000-0000-0000-0000-000000000001",
                "vuln_type": "idor",
                "title": "IDOR in /documents/<doc_id> (Missing ownership / permission check)",
                "severity": "HIGH",
                "file_path": "fixtures/vulnerable_app/app.py",
                "line_start": 82,
                "line_end": 89,
                "target_function": "get_document",
            },
        ]
    return results


@router.post("/run", response_model=ChallengeOut)
def run_trial(
    req: ChallengeRunRequest,
    db: Optional[Session] = Depends(get_optional_db),
) -> ChallengeOut:
    """Run an automated Fix Court trial evaluating AI candidates."""
    try:
        challenge = run_challenge_trial(
            finding_id=req.finding_id,
            count=req.count,
            use_cache=req.use_cache,
            temperature=req.temperature,
            db=db,
        )
        return challenge
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Challenge trial failed: {exc}")


@router.post("/submit", response_model=CandidateOut)
def submit_judge_patch(
    req: JudgeSubmitRequest,
    db: Optional[Session] = Depends(get_optional_db),
) -> CandidateOut:
    """Submit a developer or external AI replacement function to face the court."""
    try:
        candidate = submit_judge_replacement(
            finding_id=req.finding_id,
            source_code=req.source_code,
            candidate_name=req.candidate_name,
            db=db,
        )
        return candidate
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Judge submission failed: {exc}")


@router.get("/{challenge_id}", response_model=ChallengeOut)
def get_challenge_results(challenge_id: uuid.UUID) -> ChallengeOut:
    """Retrieve full Fix Court challenge trial results."""
    chal = get_challenge(challenge_id)
    if not chal:
        raise HTTPException(status_code=404, detail="Challenge trial not found")
    return chal


@router.get("/{challenge_id}/candidates/{candidate_id}", response_model=CandidateOut)
def get_candidate_details(challenge_id: uuid.UUID, candidate_id: uuid.UUID) -> CandidateOut:
    """Retrieve individual candidate evidence, gauntlet, and forensic results."""
    candidate = get_candidate(challenge_id, candidate_id)
    if not candidate:
        raise HTTPException(status_code=404, detail="Candidate not found")
    return candidate
