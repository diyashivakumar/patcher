import uuid
from datetime import datetime

from pydantic import BaseModel, Field

from app.schemas.common import ORMModel
from app.schemas.scan import ScanSummary


class FixtureInfo(BaseModel):
    name: str
    title: str
    description: str
    verification_scenarios: list[str]


class ProjectCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=2000)
    fixture_name: str = Field(description="Bundled fixture to copy, e.g. 'student_portal'")


class ProjectOut(ORMModel):
    id: uuid.UUID
    name: str
    description: str | None
    source_type: str
    fixture_name: str | None
    file_count: int
    total_bytes: int
    verification_supported: bool = False
    verification_scenarios: list[str] = []
    scan_count: int = 0
    latest_scan: ScanSummary | None = None
    created_at: datetime
    updated_at: datetime


class ProjectDetail(ProjectOut):
    scans: list[ScanSummary] = []
    upload_skipped: list[dict] = []
