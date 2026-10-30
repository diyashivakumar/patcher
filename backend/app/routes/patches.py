import uuid

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.database import get_db
from app.errors import ApiError, not_found
from app.models import Finding, Patch
from app.models.audit_log import record
from app.models.base import utcnow
from app.patching import applier
from app.patching.generator import PatchNotSupported, generate_patch
from app.schemas.patch import PatchApply, PatchGenerate, PatchOut, PatchRollback
from app.serializers import patch_out
from app.services import storage

router = APIRouter(tags=["patches"])

ROLLBACK_FROM = {"APPLIED", "VERIFIED", "REJECTED"}


def _get(db, patch_id):
    patch = db.get(Patch, patch_id)
    if not patch:
        raise not_found("Patch")
    return patch


@router.post("/patches/generate", response_model=PatchOut, status_code=201)
def generate(body: PatchGenerate, db: Session = Depends(get_db)):
    """Propose a patch. Nothing on disk changes until /apply is called with approval."""
    finding = db.get(Finding, body.finding_id)
    if not finding:
        raise not_found("Finding")
    active = next((p for p in finding.patches if p.status in ROLLBACK_FROM), None)
    if active:
        raise ApiError(409, "patch_already_applied",
                       f"Patch {active.id} ({active.strategy}, {active.status}) is still applied for this finding. "
                       "Roll it back before generating another.", {"patch_id": str(active.id)})
    try:
        target = storage.safe_join(storage.source_dir(finding.project_id), finding.file_path)
        text = applier.read_source(target)
    except (OSError, storage.UploadRejected) as exc:
        raise ApiError(409, "source_unavailable", f"Cannot read {finding.file_path}: {exc}") from exc
    try:
        proposal = generate_patch(finding.vuln_type, finding.evidence, text, finding.file_path, body.strategy)
    except PatchNotSupported as exc:
        raise ApiError(422, "patch_not_supported", str(exc)) from exc
    except SyntaxError as exc:
        raise ApiError(409, "source_changed", "The file no longer parses; re-scan the project") from exc
    patch = Patch(finding_id=finding.id, project_id=finding.project_id, status="PROPOSED", **vars(proposal))
    db.add(patch)
    db.flush()
    record(db, "patch.generate", "patch", patch.id, finding.project_id, strategy=patch.strategy)
    db.commit()
    db.refresh(patch)
    return patch_out(patch)


@router.get("/patches/{patch_id}", response_model=PatchOut)
def get_patch(patch_id: uuid.UUID, db: Session = Depends(get_db)):
    return patch_out(_get(db, patch_id))


@router.post("/patches/{patch_id}/apply", response_model=PatchOut)
def apply(patch_id: uuid.UUID, body: PatchApply, db: Session = Depends(get_db)):
    patch = _get(db, patch_id)
    if not body.approved:
        raise ApiError(403, "approval_required", "Patches are only applied with explicit approval (approved=true)")
    if patch.status != "PROPOSED":
        raise ApiError(409, "invalid_state", f"Patch is {patch.status}; only PROPOSED patches can be applied")
    try:
        backup = applier.apply_patch(storage.source_dir(patch.project_id), storage.backups_dir(patch.project_id), patch)
    except applier.PatchConflict as exc:
        record(db, "patch.apply_failed", "patch", patch.id, patch.project_id, body.approved_by, error=str(exc))
        db.commit()
        raise ApiError(409, "patch_conflict", str(exc)) from exc
    now = utcnow()
    patch.status, patch.backup_path = "APPLIED", backup
    patch.approved_by, patch.approved_at, patch.applied_at = body.approved_by, now, now
    record(db, "patch.apply", "patch", patch.id, patch.project_id, body.approved_by, file=patch.file_path)
    db.commit()
    db.refresh(patch)
    return patch_out(patch)


@router.post("/patches/{patch_id}/rollback", response_model=PatchOut)
def rollback(patch_id: uuid.UUID, body: PatchRollback, db: Session = Depends(get_db)):
    patch = _get(db, patch_id)
    if patch.status not in ROLLBACK_FROM:
        raise ApiError(409, "invalid_state", f"Patch is {patch.status}; nothing to roll back")
    try:
        applier.rollback_patch(storage.source_dir(patch.project_id), patch)
    except applier.PatchConflict as exc:
        raise ApiError(409, "rollback_conflict", f"{exc} A backup of the pre-patch file is kept at "
                                                 f"backups/{patch.backup_path}.") from exc
    patch.status, patch.rolled_back_at = "ROLLED_BACK", utcnow()
    record(db, "patch.rollback", "patch", patch.id, patch.project_id, body.requested_by, reason=body.reason)
    db.commit()
    db.refresh(patch)
    return patch_out(patch)
