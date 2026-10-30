import uuid
from datetime import datetime

from pydantic import BaseModel

from app.schemas.common import ORMModel


class PatchBrief(ORMModel):
    id: uuid.UUID
    strategy: str
    status: str
    created_at: datetime


class FindingOut(ORMModel):
    id: uuid.UUID
    scan_id: uuid.UUID
    project_id: uuid.UUID
    vuln_type: str
    title: str
    severity: str
    severity_rationale: str
    confidence: str
    cwe: str
    file_path: str
    line_start: int
    line_end: int
    code_snippet: str
    snippet_start_line: int
    evidence: dict
    explanation: str
    impact: str
    remediation: str
    detection_method: str
    created_at: datetime


class FindingDetail(FindingOut):
    patches: list[PatchBrief] = []
    available_strategies: list[str] = []
    verification_supported: bool = False


class AIExplanation(BaseModel):
    available: bool
    model: str | None
    text: str | None
    message: str
    advisory: str
