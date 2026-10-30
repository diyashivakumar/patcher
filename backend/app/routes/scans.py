import uuid

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.database import get_db
from app.errors import not_found
from app.models import Finding, Project, Scan
from app.models.audit_log import record
from app.models.base import utcnow
from app.scanner.engine import scan_directory
from app.schemas.finding import FindingOut
from app.schemas.scan import ScanCreate, ScanSummary
from app.serializers import scan_out
from app.services import storage

router = APIRouter(tags=["scans"])


@router.post("/scans", response_model=ScanSummary, status_code=201)
def create_scan(body: ScanCreate, db: Session = Depends(get_db)):
    """Scan the project's CURRENT working copy (so a re-scan after patching reflects the patch)."""
    project = db.get(Project, body.project_id)
    if not project:
        raise not_found("Project")
    scan = Scan(project_id=project.id, status="RUNNING", started_at=utcnow(), warnings=[])
    db.add(scan)
    try:
        results, files_scanned, warnings = scan_directory(storage.source_dir(project.id))
    except OSError as exc:
        scan.status, scan.error = "FAILED", f"Could not read project files: {exc}"
    else:
        for f in results:
            scan.findings.append(Finding(project_id=project.id, **vars(f)))
        scan.status = "COMPLETED"
        scan.files_scanned = files_scanned
        scan.findings_count = len(results)
        scan.warnings = warnings
    scan.completed_at = utcnow()
    db.flush()
    record(db, "scan.run", "scan", scan.id, project.id, status=scan.status, findings=scan.findings_count)
    db.commit()
    db.refresh(scan)
    return scan_out(scan)


@router.get("/scans/{scan_id}", response_model=ScanSummary)
def get_scan(scan_id: uuid.UUID, db: Session = Depends(get_db)):
    scan = db.get(Scan, scan_id)
    if not scan:
        raise not_found("Scan")
    return scan_out(scan)


@router.get("/scans/{scan_id}/findings", response_model=list[FindingOut])
def get_scan_findings(scan_id: uuid.UUID, db: Session = Depends(get_db)):
    scan = db.get(Scan, scan_id)
    if not scan:
        raise not_found("Scan")
    return [FindingOut.model_validate(f) for f in scan.findings]
