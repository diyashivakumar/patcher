import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, model_validator

from app.schemas.common import ORMModel


class VerificationRunCreate(BaseModel):
    """Either patch_id (Proof-of-Fix) or project_id + scenario (baseline exploit replay)."""

    patch_id: uuid.UUID | None = None
    project_id: uuid.UUID | None = None
    scenario: Literal["sqli", "idor"] | None = None

    @model_validator(mode="after")
    def one_mode(self):
        if self.patch_id is None and (self.project_id is None or self.scenario is None):
            raise ValueError("Provide patch_id, or both project_id and scenario")
        if self.patch_id is not None and (self.project_id or self.scenario):
            raise ValueError("Provide patch_id alone, or project_id + scenario, not both")
        return self


class TestResultOut(ORMModel):
    phase: str
    category: str
    test_id: str
    name: str
    description: str
    status: str
    expected: str
    actual: str
    exploit_succeeded: bool | None
    evidence: dict
    privilege_map: dict | None


class VerificationRunOut(ORMModel):
    id: uuid.UUID
    project_id: uuid.UUID
    patch_id: uuid.UUID | None
    kind: str
    scenario: str
    status: str
    verdict: str | None
    verdict_reasons: list[str]
    original_vulnerability_reproduced: bool | None
    exploit_blocked_after_patch: bool | None
    regressions_pass_after_patch: bool | None
    phase_summaries: dict
    error: str | None
    started_at: datetime
    completed_at: datetime | None
    duration_ms: int | None
    created_at: datetime


class VerificationRunDetail(VerificationRunOut):
    patch_status: str | None = None
    test_results: list[TestResultOut] = []
