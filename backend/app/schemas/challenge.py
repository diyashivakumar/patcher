import uuid

from pydantic import BaseModel


class ChainImpactRequest(BaseModel):
    project_id: uuid.UUID | None = None


class ChainStep(BaseModel):
    step_id: str
    name: str
    reached: bool
    succeeded: bool
    stolen: list[str]
    canary_ids: list[str]
    actor: str | None
    status_code: int | None
    actual: str


class ChainMatrixRow(BaseModel):
    copy_id: str
    label: str
    applied_fixes: list[str]
    steps_reached: int
    reached_final: bool
    chain_succeeded: bool
    stolen: list[str]
    final_records: list[str]
    steps: list[ChainStep]
    ledger: list[dict]
    breach_bill: dict


class BestSingleFix(BaseModel):
    copy_id: str
    label: str
    applied_fixes: list[str]
    steps_reached: int
    records_exposed: int


class ChainImpactResult(BaseModel):
    scenario: str
    total_steps: int
    matrix: list[ChainMatrixRow]
    best_single_fix: BestSingleFix | None
    canary_records: str
