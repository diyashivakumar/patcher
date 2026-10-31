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


class GitHubImportRequest(BaseModel):
    url: str = Field(min_length=5, max_length=2048, description="Public GitHub repo URL, e.g. https://github.com/owner/repo")
    branch: str | None = Field(default=None, max_length=255, description="Branch to import; defaults to the repo default branch")
    name: str | None = Field(default=None, max_length=200, description="Optional project name; defaults to owner/repo")


class GitHubBranch(BaseModel):
    name: str
    commit: str = ""


class GitHubRepoInfo(BaseModel):
    owner: str
    repo: str
    full_name: str
    description: str | None = None
    default_branch: str
    is_public: bool
    html_url: str
    branches: list[GitHubBranch] = []


class ProjectOut(ORMModel):
    id: uuid.UUID
    name: str
    description: str | None
    source_type: str
    fixture_name: str | None
    source_url: str | None = None
    source_ref: str | None = None
    source_commit: str | None = None
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
