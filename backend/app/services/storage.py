"""Project file storage and safe ZIP extraction.

Layout on disk (STORAGE_DIR/projects/<project_id>/):
  original/   pristine copy, never modified (the "before" side of verification)
  source/     working copy that approved patches are applied to
  backups/    per-patch backups of files taken before each apply

Uploaded code is only ever READ (scanned) -- it is never imported or executed.
"""
import io
import re
import shutil
import stat
import tempfile
import zipfile
from pathlib import Path, PurePosixPath

from app.config import get_settings

# Bundled practice fixtures that the verification runner knows how to test.
FIXTURES = {
    "student_portal": {
        "path": "vulnerable_app",
        "title": "Student Document Portal (deliberately vulnerable)",
        "description": "Flask + SQLite practice app with a SQL injection in /search and an IDOR in "
                       "/documents/<id>. Synthetic data only.",
        "verification_scenarios": ["sqli", "idor"],
    },
}

ALLOWED_EXTENSIONS = {".py", ".txt", ".md", ".sql", ".html", ".htm", ".css", ".js", ".json", ".toml",
                      ".cfg", ".ini", ".yml", ".yaml", ".jinja", ".j2", ".csv"}
SKIP_DIRS = {".git", "__pycache__", "venv", ".venv", "node_modules", ".tox", ".idea", ".vscode"}
SECRET_NAME = re.compile(r"(^\.env(\..*)?$|\.pem$|\.key$|^id_rsa|\.p12$|\.pfx$|^secrets?\.)", re.IGNORECASE)
MAX_COMPRESSION_RATIO = 100


class UploadRejected(Exception):
    pass


def projects_root() -> Path:
    root = Path(get_settings().STORAGE_DIR).resolve() / "projects"
    root.mkdir(parents=True, exist_ok=True)
    return root


def project_dir(project_id) -> Path:
    return projects_root() / str(project_id)


def original_dir(project_id) -> Path:
    return project_dir(project_id) / "original"


def source_dir(project_id) -> Path:
    return project_dir(project_id) / "source"


def backups_dir(project_id) -> Path:
    return project_dir(project_id) / "backups"


def safe_join(root, relative) -> Path:
    """Join and refuse anything that resolves outside root."""
    root = Path(root).resolve()
    target = (root / relative).resolve()
    if target != root and root not in target.parents:
        raise UploadRejected(f"Path escapes the project directory: {relative}")
    return target


def _tree_stats(root: Path):
    files = [p for p in root.rglob("*") if p.is_file()]
    return len(files), sum(p.stat().st_size for p in files)


def create_from_fixture(project_id, fixture_name):
    fixture = FIXTURES.get(fixture_name)
    if not fixture:
        raise UploadRejected(f"Unknown fixture '{fixture_name}'")
    src = Path(get_settings().FIXTURES_DIR).resolve() / fixture["path"]
    if not (src / "app.py").is_file():
        raise UploadRejected(f"Fixture files not found at {src}")
    ignore = shutil.ignore_patterns("__pycache__", "*.pyc", "*.sqlite3", "*.db")
    shutil.copytree(src, original_dir(project_id), ignore=ignore)
    shutil.copytree(src, source_dir(project_id), ignore=ignore)
    return _tree_stats(original_dir(project_id))


def extract_upload(project_id, data: bytes):
    """Validate and extract a ZIP into the project's original/ and source/ dirs.

    Returns (file_count, total_bytes, skipped) where skipped lists files not extracted and why.
    Raises UploadRejected for anything unsafe (traversal, symlinks, bombs, oversize).
    """
    settings = get_settings()
    if len(data) > settings.MAX_UPLOAD_MB * 1024 * 1024:
        raise UploadRejected(f"ZIP is larger than {settings.MAX_UPLOAD_MB} MB")
    if not data.startswith(b"PK\x03\x04"):
        raise UploadRejected("File is not a ZIP archive")
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as exc:
        raise UploadRejected("Corrupt ZIP archive") from exc

    limit = settings.MAX_EXTRACTED_MB * 1024 * 1024
    plan, skipped, total = [], [], 0
    for info in archive.infolist():
        name = info.filename.replace("\\", "/")
        pure = PurePosixPath(name)
        if name.startswith("/") or re.match(r"^[A-Za-z]:", name) or ".." in pure.parts:
            raise UploadRejected(f"Unsafe path in ZIP (path traversal attempt): {info.filename}")
        if stat.S_ISLNK(info.external_attr >> 16):
            raise UploadRejected(f"Symbolic links are not allowed in uploads: {info.filename}")
        if info.is_dir():
            continue
        if any(part in SKIP_DIRS for part in pure.parts):
            skipped.append({"path": name, "reason": "ignored directory"})
            continue
        if SECRET_NAME.search(pure.name):
            skipped.append({"path": name, "reason": "possible secret file; not stored"})
            continue
        if pure.suffix.lower() not in ALLOWED_EXTENSIONS:
            skipped.append({"path": name, "reason": f"file type {pure.suffix or '(none)'} not accepted"})
            continue
        if info.compress_size and info.file_size / info.compress_size > MAX_COMPRESSION_RATIO:
            raise UploadRejected(f"Suspicious compression ratio (possible ZIP bomb): {info.filename}")
        total += info.file_size
        if total > limit:
            raise UploadRejected(f"Extracted size would exceed {settings.MAX_EXTRACTED_MB} MB")
        plan.append((info, name))
    if len(plan) > settings.MAX_UPLOAD_FILES:
        raise UploadRejected(f"ZIP contains more than {settings.MAX_UPLOAD_FILES} accepted files")
    if not any(name.endswith(".py") for _, name in plan):
        raise UploadRejected("ZIP contains no Python (.py) files to scan")

    with tempfile.TemporaryDirectory(prefix="patchproof-upload-") as tmp:
        staging = Path(tmp) / "src"
        staging.mkdir()
        for info, name in plan:
            target = safe_join(staging, name)
            target.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(info) as src:
                content = src.read(info.file_size + 1)
            if len(content) != info.file_size:
                raise UploadRejected(f"Declared size does not match content: {name}")
            target.write_bytes(content)
        shutil.copytree(staging, original_dir(project_id))
        shutil.copytree(staging, source_dir(project_id))
    count, size = _tree_stats(original_dir(project_id))
    return count, size, skipped


def delete_project_files(project_id):
    shutil.rmtree(project_dir(project_id), ignore_errors=True)
