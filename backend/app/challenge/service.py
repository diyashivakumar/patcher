"""Fix Court service: orchestrates candidate generation, evaluation, and courtroom verdicts."""
import ast
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from sqlalchemy.orm import Session

from app.challenge.generator import generate_candidates
from app.challenge.runner import evaluate_candidate, _find_function_span
from app.challenge.schemas import ChallengeOut, CandidateOut, VerdictType
from app.config import REPO_ROOT
from app.models.finding import Finding

# In-memory trial cache for Fix Court sessions
_CHALLENGES: dict[uuid.UUID, ChallengeOut] = {}


def _get_app_py_source() -> str:
    path = REPO_ROOT / "fixtures" / "vulnerable_app" / "app.py"
    if not path.exists():
        raise FileNotFoundError(f"Fixture app not found at {path}")
    return path.read_text(encoding="utf-8")


def get_finding_context(finding_id: uuid.UUID, db: Optional[Session] = None) -> dict:
    """Retrieve vulnerability details and function context for a finding."""
    vuln_type = "sqli"
    project_id = uuid.uuid4()
    file_path = "fixtures/vulnerable_app/app.py"

    if db:
        finding = db.get(Finding, finding_id)
        if finding:
            vuln_type = finding.vuln_type.lower()
            project_id = finding.project_id
            file_path = finding.file_path

    target_func = "search" if vuln_type == "sqli" else "get_document"
    expected_args = [] if vuln_type == "sqli" else ["doc_id"]

    source_text = _get_app_py_source()
    try:
        _, _, orig_func_code = _find_function_span(source_text, target_func)
    except Exception:
        orig_func_code = ""

    return {
        "finding_id": finding_id,
        "project_id": project_id,
        "vuln_type": vuln_type,
        "target_function": target_func,
        "expected_args": expected_args,
        "file_path": file_path,
        "original_code": orig_func_code,
    }


def run_challenge_trial(
    finding_id: uuid.UUID,
    count: int = 8,
    use_cache: bool = True,
    temperature: float = 0.4,
    db: Optional[Session] = None,
) -> ChallengeOut:
    """Run a Fix Court trial against AI-generated candidates."""
    ctx = get_finding_context(finding_id, db)
    challenge_id = uuid.uuid4()
    now = datetime.now(timezone.utc)

    # 1. Generate or fetch candidates
    raw_candidates, source_label = generate_candidates(
        vuln_type=ctx["vuln_type"],
        target_func_name=ctx["target_function"],
        original_func_code=ctx["original_code"],
        count=count,
        use_cache=use_cache,
        temperature=temperature,
    )

    evaluated_candidates: list[CandidateOut] = []
    verdict_counts: dict[str, int] = {
        "GENUINE": 0,
        "FAKE_FIX": 0,
        "BYPASSED": 0,
        "OVER_RESTRICTIVE": 0,
        "DATA_LEAK": 0,
        "REJECTED_UNSAFE_CODE": 0,
        "INCONCLUSIVE": 0,
    }

    # 2. Evaluate each candidate in isolated harness
    for idx, c in enumerate(raw_candidates):
        cid = uuid.uuid4()
        source_type = "cached" if use_cache else "ollama"
        evaluated = evaluate_candidate(
            challenge_id=challenge_id,
            candidate_id=cid,
            name=c.get("name", f"Candidate #{idx + 1}"),
            source_type=c.get("source_type", source_type),
            model_name=c.get("model_name") or c.get("model", "gemma4:e2b"),
            source_code=c.get("source_code") or c.get("code", ""),
            vuln_type=ctx["vuln_type"],
            target_func_name=ctx["target_function"],
            expected_args=ctx["expected_args"],
            created_at=now,
        )
        evaluated_candidates.append(evaluated)
        v = evaluated.verdict
        verdict_counts[v] = verdict_counts.get(v, 0) + 1

    genuine_count = verdict_counts.get("GENUINE", 0)
    total_count = len(evaluated_candidates)
    scoreboard = f"{genuine_count} / {total_count} GENUINE"

    challenge = ChallengeOut(
        id=challenge_id,
        project_id=ctx["project_id"],
        finding_id=finding_id,
        vuln_type=ctx["vuln_type"],
        target_function=ctx["target_function"],
        file_path=ctx["file_path"],
        status="COMPLETED",
        total_candidates=total_count,
        scoreboard=scoreboard,
        verdict_counts=verdict_counts,
        candidates=evaluated_candidates,
        created_at=now,
    )

    _CHALLENGES[challenge_id] = challenge
    return challenge


def submit_judge_replacement(
    finding_id: uuid.UUID,
    source_code: str,
    candidate_name: Optional[str] = None,
    db: Optional[Session] = None,
) -> CandidateOut:
    """Put a custom developer/AI replacement function on trial."""
    ctx = get_finding_context(finding_id, db)
    cid = uuid.uuid4()
    challenge_id = uuid.uuid4()

    name = candidate_name or "Judge Custom Submission"
    evaluated = evaluate_candidate(
        challenge_id=challenge_id,
        candidate_id=cid,
        name=name,
        source_type="judge_submission",
        model_name="Manual / External AI",
        source_code=source_code,
        vuln_type=ctx["vuln_type"],
        target_func_name=ctx["target_function"],
        expected_args=ctx["expected_args"],
    )

    # If there's an existing challenge session for this finding, append it
    for chal in _CHALLENGES.values():
        if chal.finding_id == finding_id:
            chal.candidates.insert(0, evaluated)
            chal.total_candidates = len(chal.candidates)
            v = evaluated.verdict
            chal.verdict_counts[v] = chal.verdict_counts.get(v, 0) + 1
            genuine_count = chal.verdict_counts.get("GENUINE", 0)
            chal.scoreboard = f"{genuine_count} / {chal.total_candidates} GENUINE"
            break

    return evaluated


def get_challenge(challenge_id: uuid.UUID) -> Optional[ChallengeOut]:
    """Retrieve challenge trial results."""
    return _CHALLENGES.get(challenge_id)


def get_candidate(challenge_id: uuid.UUID, candidate_id: uuid.UUID) -> Optional[CandidateOut]:
    """Retrieve specific candidate evidence."""
    chal = _CHALLENGES.get(challenge_id)
    if not chal:
        return None
    for c in chal.candidates:
        if c.id == candidate_id:
            return c
    return None
