"""GitHub import tests. GitHub is never contacted; metadata/archive calls are mocked.

Covers the hostname allowlist (lookalike rejection), reuse of the ZIP validation
pipeline, and that imported code is stored but never executed.
"""
import io
import zipfile

import pytest

from app.services import github_import as gh


def make_zip(entries):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    return buf.getvalue()


# ---- URL parsing / hostname allowlist -----------------------------------
def test_parse_valid_url():
    assert gh.parse_github_url("https://github.com/owner/repo") == ("owner", "repo", None)


def test_parse_strips_dot_git_and_tree_ref():
    assert gh.parse_github_url("https://github.com/owner/repo.git") == ("owner", "repo", None)
    assert gh.parse_github_url("https://github.com/owner/repo/tree/dev") == ("owner", "repo", "dev")


@pytest.mark.parametrize("url", [
    "https://github.com.evil.com/owner/repo",   # suffix lookalike
    "https://evilgithub.com/owner/repo",        # prefix lookalike
    "https://raw.githubusercontent.com/o/r/main/f.py",
    "https://gitlab.com/owner/repo",
    "https://github.io/owner/repo",
    "http://169.254.169.254/owner/repo",
    "https://github.com/owner",                 # missing repo
    "ftp://github.com/owner/repo",
])
def test_parse_rejects_non_github_and_lookalikes(url):
    with pytest.raises(gh.GitHubImportError):
        gh.parse_github_url(url)


# ---- download size cap ---------------------------------------------------
def test_download_zip_enforces_size_cap(monkeypatch):
    monkeypatch.setattr(gh.get_settings(), "MAX_UPLOAD_MB", 0)  # cap = 0 bytes

    class FakeStream:
        status_code = 200
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def iter_bytes(self): yield b"PK\x03\x04" + b"x" * 1024

    class FakeClient:
        def __init__(self, *a, **k): pass
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def stream(self, *a, **k): return FakeStream()

    monkeypatch.setattr(gh.httpx, "Client", FakeClient)
    with pytest.raises(gh.GitHubImportError, match="exceeds"):
        gh.download_zip("owner", "repo", "main")


# ---- API: import flow ----------------------------------------------------
def _mock_github(monkeypatch, zip_bytes):
    monkeypatch.setattr(gh, "get_repo_meta", lambda o, r: {
        "owner": o, "repo": r, "full_name": f"{o}/{r}", "description": "demo",
        "default_branch": "main", "is_public": True, "html_url": f"https://github.com/{o}/{r}"})
    monkeypatch.setattr(gh, "resolve_ref_sha", lambda o, r, ref: "a" * 40)
    monkeypatch.setattr(gh, "download_zip", lambda o, r, ref: zip_bytes)


def test_import_github_creates_project(client, monkeypatch):
    _mock_github(monkeypatch, make_zip({"repo-main/app.py": "print('hello')\n", "repo-main/.git/config": "x"}))
    r = client.post("/api/projects/import/github",
                    json={"url": "https://github.com/owner/repo", "branch": "main"})
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["source_type"] == "github"
    assert body["source_url"] == "https://github.com/owner/repo"
    assert body["source_ref"] == "main"
    assert body["source_commit"] == "a" * 40
    assert body["file_count"] == 1  # .git contents dropped by the pipeline


def test_import_github_rejects_bad_url_before_fetch(client):
    r = client.post("/api/projects/import/github", json={"url": "https://gitlab.com/o/r"})
    assert r.status_code == 422
    assert r.json()["error"]["code"] == "github_import_failed"


def test_import_github_rejects_archive_without_python(client, monkeypatch):
    _mock_github(monkeypatch, make_zip({"repo-main/README.md": "# hi"}))
    r = client.post("/api/projects/import/github", json={"url": "https://github.com/owner/repo"})
    assert r.status_code == 422
    assert r.json()["error"]["code"] == "upload_rejected"


def test_import_github_rejects_private_repo(client, monkeypatch):
    def private(o, r):
        raise gh.GitHubImportError("Only public repositories can be imported.", status=422)
    monkeypatch.setattr(gh, "get_repo_meta", private)
    r = client.post("/api/projects/import/github", json={"url": "https://github.com/owner/secret"})
    assert r.status_code == 422
    assert "public" in r.json()["error"]["message"].lower()


def test_branches_endpoint(client, monkeypatch):
    monkeypatch.setattr(gh, "get_repo_meta", lambda o, r: {
        "owner": o, "repo": r, "full_name": f"{o}/{r}", "description": None,
        "default_branch": "main", "is_public": True, "html_url": f"https://github.com/{o}/{r}"})
    monkeypatch.setattr(gh, "list_branches", lambda o, r: [{"name": "main", "commit": "b" * 40}])
    r = client.get("/api/projects/import/github/branches", params={"url": "https://github.com/owner/repo"})
    assert r.status_code == 200
    body = r.json()
    assert body["default_branch"] == "main"
    assert body["branches"][0]["name"] == "main"
