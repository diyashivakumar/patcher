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
    # Runner schema 1.1; null for runs recorded before the Gauntlet existed. Shapes: docs/testing_contract.md
    gauntlet: dict | None = None
    forensics: dict | None = None


class RegressionCaseOut(ORMModel):
    id: uuid.UUID
    fixture_name: str
    scenario: str
    fingerprint: str
    kind: str
    variation: str
    description: str
    input: dict
    check: dict | None = None  # oracle replayed with the case (e.g. injection probe)
    source_variant_id: str
    source_run_id: uuid.UUID | None
    source_patch_id: uuid.UUID | None
    original_outcome: dict
    patched_outcome: dict
    times_seen: int
    last_seen_run_id: uuid.UUID | None
    created_at: datetime
    updated_at: datetime
