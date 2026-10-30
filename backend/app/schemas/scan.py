import uuid
from datetime import datetime

from pydantic import BaseModel

from app.schemas.common import ORMModel


class ScanCreate(BaseModel):
    project_id: uuid.UUID


class ScanSummary(ORMModel):
    id: uuid.UUID
    project_id: uuid.UUID
    status: str
    started_at: datetime
    completed_at: datetime | None
    files_scanned: int
    findings_count: int
    severity_counts: dict[str, int] = {}
    warnings: list[str]
    error: str | None
