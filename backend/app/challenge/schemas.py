import uuid
from datetime import datetime
from typing import Any, Literal
from pydantic import BaseModel, Field

VerdictType = Literal[
    "GENUINE",
    "FAKE_FIX",
    "BYPASSED",
    "OVER_RESTRICTIVE",
    "DATA_LEAK",
    "REJECTED_UNSAFE_CODE",
    "INCONCLUSIVE",
]

SourceType = Literal["ollama", "cached", "judge_submission", "reference"]


class ChallengeRunRequest(BaseModel):
    finding_id: uuid.UUID
    count: int = Field(default=8, ge=1, le=12)
    use_cache: bool = True
    temperature: float = Field(default=0.4, ge=0.0, le=1.0)


class JudgeSubmitRequest(BaseModel):
    finding_id: uuid.UUID
    source_code: str
    candidate_name: str | None = None


class GauntletTestEvidence(BaseModel):
    payload_id: str
    name: str
    payload: str
    category: str  # "original_exploit" | "variant_gauntlet" | "regression"
    expected: str
    actual: str
    passed: bool
    exploit_succeeded: bool | None = None
    response_status: int | None = None
    evidence_snippet: str | None = None


class ForensicsEvidence(BaseModel):
    canary_detected: bool
    detected_markers: list[str] = Field(default_factory=list)
    leaked_excerpts: list[str] = Field(default_factory=list)
    inspected_responses: int = 0
    clean_responses: int = 0


class SafetyValidationResult(BaseModel):
    valid: bool
    rejection_reason: str | None = None
    inspected_constructs: list[str] = Field(default_factory=list)
    function_name: str | None = None


class CandidateOut(BaseModel):
    id: uuid.UUID
    challenge_id: uuid.UUID
    name: str
    source_type: SourceType
    model_name: str | None = None
    source_code: str
    diff: str
    safety_status: Literal["PASSED", "REJECTED"]
    safety_reason: str | None = None
    verdict: VerdictType
    verdict_rationale: str
    convicting_test_id: str | None = None
    security_passed: bool
    regression_passed: bool
    gauntlet_passed: bool
    forensics_clean: bool
    gauntlet_results: list[GauntletTestEvidence] = Field(default_factory=list)
    forensics_results: ForensicsEvidence | None = None
    created_at: datetime


class ChallengeOut(BaseModel):
    id: uuid.UUID
    project_id: uuid.UUID
    finding_id: uuid.UUID
    vuln_type: str
    target_function: str
    file_path: str
    status: Literal["RUNNING", "COMPLETED", "FAILED"]
    total_candidates: int
    scoreboard: str  # e.g. "3 / 8 GENUINE"
    verdict_counts: dict[str, int]
    candidates: list[CandidateOut]
    created_at: datetime

