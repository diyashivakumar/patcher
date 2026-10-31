import uuid
from datetime import datetime

from pydantic import BaseModel, Field

from app.schemas.common import ORMModel


class SiteCheckCreate(BaseModel):
    url: str = Field(min_length=3, max_length=2048, description="Public http(s) URL to assess")
    authorized: bool = Field(default=False, description="Confirms the requester is permitted to assess this site")


class CheckItem(BaseModel):
    name: str
    status: str                 # PASS | WARNING | INFO | ERROR
    evidence: str | None = None
    explanation: str
    remediation: str | None = None
    checked_at: str | None = None


class SiteCheckOut(ORMModel):
    id: uuid.UUID
    url: str
    host: str
    authorized: bool
    status: str                 # COMPLETED | ERROR
    final_url: str | None = None
    resolved_ips: list[str] = []
    redirect_chain: list[dict] = []
    posture: dict = {}
    checks: list[CheckItem] = []
    error: str | None = None
    disclaimer: str = ""
    created_at: datetime
    updated_at: datetime
