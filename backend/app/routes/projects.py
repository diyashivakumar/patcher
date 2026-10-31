import uuid

from fastapi import APIRouter, Depends, File, Form, UploadFile
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.database import get_db
from app.errors import ApiError, not_found
from app.models import Project
from app.models.audit_log import record
from app.schemas.project import (FixtureInfo, GitHubBranch, GitHubImportRequest, GitHubRepoInfo,
                                  ProjectCreate, ProjectDetail, ProjectOut)
from app.serializers import project_out
from app.services import github_import, storage

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
    db.flush()  # insert the project before its audit row (audit_logs.project_id FK)
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
    db.flush()  # insert the project before its audit row (audit_logs.project_id FK)
    record(db, "project.upload", "project", project.id, project.id, filename=file.filename,
           files=project.file_count, skipped=len(skipped))
    db.commit()
    db.refresh(project)
    return project_out(project, detail=True, upload_skipped=skipped)


@router.get("/projects/import/github/branches", response_model=GitHubRepoInfo)
def github_repo_info(url: str):
    """Look up a public GitHub repo's metadata and branches so the user can pick one to import."""
    try:
        owner, repo, _ = github_import.parse_github_url(url)
        meta = github_import.get_repo_meta(owner, repo)
        branches = github_import.list_branches(owner, repo)
    except github_import.GitHubImportError as exc:
        raise ApiError(exc.status, "github_import_failed", str(exc)) from exc
    return GitHubRepoInfo(**meta, branches=[GitHubBranch(**b) for b in branches])


@router.post("/projects/import/github", response_model=ProjectDetail, status_code=201)
def import_github(body: GitHubImportRequest, db: Session = Depends(get_db)):
    """Import a PUBLIC GitHub repository by downloading its branch archive and running it through
    the same ZIP validation/scanning pipeline as uploads. Imported code is never executed."""
    try:
        owner, repo, url_ref = github_import.parse_github_url(body.url)
        meta = github_import.get_repo_meta(owner, repo)
        ref = body.branch or url_ref or meta["default_branch"]
        commit = github_import.resolve_ref_sha(owner, repo, ref)
        data = github_import.download_zip(owner, repo, ref)
    except github_import.GitHubImportError as exc:
        raise ApiError(exc.status, "github_import_failed", str(exc)) from exc

    project = Project(id=uuid.uuid4(), name=body.name or meta["full_name"], description=meta.get("description"),
                      source_type="github", source_url=meta["html_url"], source_ref=ref, source_commit=commit)
    try:
        project.file_count, project.total_bytes, skipped = storage.extract_upload(project.id, data)
    except storage.UploadRejected as exc:
        storage.delete_project_files(project.id)
        raise ApiError(422, "upload_rejected", str(exc)) from exc
    db.add(project)
    db.flush()
    record(db, "project.import_github", "project", project.id, project.id,
           repo=meta["full_name"], ref=ref, commit=commit, files=project.file_count, skipped=len(skipped))
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
