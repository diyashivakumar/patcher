import uuid

from fastapi import APIRouter, Depends, File, Form, UploadFile
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.database import get_db
from app.errors import ApiError, not_found
from app.models import Project
from app.models.audit_log import record
from app.schemas.project import FixtureInfo, ProjectCreate, ProjectDetail, ProjectOut
from app.serializers import project_out
from app.services import storage

router = APIRouter(tags=["projects"])


@router.get("/fixtures", response_model=list[FixtureInfo])
def list_fixtures():
    return [FixtureInfo(name=k, title=v["title"], description=v["description"],
                        verification_scenarios=v["verification_scenarios"]) for k, v in storage.FIXTURES.items()]


@router.post("/projects", response_model=ProjectDetail, status_code=201)
def create_project(body: ProjectCreate, db: Session = Depends(get_db)):
    if body.fixture_name not in storage.FIXTURES:
        raise ApiError(422, "unknown_fixture", f"Unknown fixture '{body.fixture_name}'",
                       {"available": list(storage.FIXTURES)})
    project = Project(id=uuid.uuid4(), name=body.name, description=body.description,
                      source_type="fixture", fixture_name=body.fixture_name)
    try:
        project.file_count, project.total_bytes = storage.create_from_fixture(project.id, body.fixture_name)
    except storage.UploadRejected as exc:
        storage.delete_project_files(project.id)
        raise ApiError(500, "fixture_unavailable", str(exc)) from exc
    db.add(project)
    record(db, "project.create", "project", project.id, project.id, fixture=body.fixture_name)
    db.commit()
    db.refresh(project)
    return project_out(project, detail=True)


@router.post("/projects/upload", response_model=ProjectDetail, status_code=201)
async def upload_project(
    name: str = Form(..., min_length=1, max_length=200),
    description: str | None = Form(None, max_length=2000),
    file: UploadFile = File(..., description="ZIP archive of Python source"),
    db: Session = Depends(get_db),
):
    if not (file.filename or "").lower().endswith(".zip"):
        raise ApiError(422, "invalid_upload", "Only .zip uploads are accepted")
    limit = get_settings().MAX_UPLOAD_MB * 1024 * 1024
    data = await file.read(limit + 1)
    project = Project(id=uuid.uuid4(), name=name, description=description, source_type="upload")
    try:
        project.file_count, project.total_bytes, skipped = storage.extract_upload(project.id, data)
    except storage.UploadRejected as exc:
        storage.delete_project_files(project.id)
        raise ApiError(422, "upload_rejected", str(exc)) from exc
    db.add(project)
    record(db, "project.upload", "project", project.id, project.id, filename=file.filename,
           files=project.file_count, skipped=len(skipped))
    db.commit()
    db.refresh(project)
    return project_out(project, detail=True, upload_skipped=skipped)


@router.get("/projects", response_model=list[ProjectOut])
def list_projects(db: Session = Depends(get_db)):
    projects = db.scalars(select(Project).order_by(Project.created_at.desc())).all()
    return [project_out(p) for p in projects]


@router.get("/projects/{project_id}", response_model=ProjectDetail)
def get_project(project_id: uuid.UUID, db: Session = Depends(get_db)):
    project = db.get(Project, project_id)
    if not project:
        raise not_found("Project")
    return project_out(project, detail=True)
