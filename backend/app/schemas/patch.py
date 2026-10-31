import uuid
from datetime import datetime

from pydantic import BaseModel, Field, field_validator

from app.schemas.common import ORMModel


class PatchGenerate(BaseModel):
    finding_id: uuid.UUID
    strategy: str | None = Field(default=None, description="Omit for the default safe strategy")


class PatchApply(BaseModel):
    approved: bool = Field(description="Must be true: explicit human approval")
    approved_by: str = Field(min_length=1, max_length=100)

    @field_validator("approved_by")
    @classmethod
    def _named_approver(cls, v: str) -> str:
        # QA finding: "   " used to pass and was written to the audit log as the approver.
        v = v.strip()
        if not v:
            raise ValueError("approved_by must name a person")
        return v


class PatchRollback(BaseModel):
    reason: str | None = Field(default=None, max_length=500)
    requested_by: str = Field(default="anonymous", max_length=100)


class RunBrief(ORMModel):
    id: uuid.UUID
    kind: str
    status: str
    verdict: str | None
    created_at: datetime


class PatchOut(ORMModel):
    id: uuid.UUID
    finding_id: uuid.UUID
    project_id: uuid.UUID
    vuln_type: str
    strategy: str
    is_demo_bad_patch: bool
    status: str
    file_path: str
    line_start: int
    line_end: int
    original_snippet: str
    patched_snippet: str
    diff: str
    rationale: str
    validation: dict
    approved_by: str | None
    approved_at: datetime | None
    applied_at: datetime | None
    rolled_back_at: datetime | None
    created_at: datetime
    verification_runs: list[RunBrief] = []
