"""Import a PUBLIC GitHub repository as a PatchProof project.

Security:
  * Only github.com URLs (exact hostname allowlist). No arbitrary URL fetching.
  * Metadata/archive are fetched only from api.github.com and codeload.github.com over HTTPS.
  * Public repositories only; no token is used or required.
  * The archive is size-capped on download and then handed to storage.extract_upload(),
    which already enforces ZIP traversal/symlink/bomb/size/type validation and drops .git,
    node_modules, secrets, etc. Imported code is NEVER executed.
"""
import re

import httpx

from app.config import get_settings

API = "https://api.github.com"
CODELOAD = "https://codeload.github.com"
TIMEOUT = httpx.Timeout(15.0, connect=8.0)
HEADERS = {"Accept": "application/vnd.github+json", "User-Agent": "PatchProof-GitHubImport/0.1",
           "X-GitHub-Api-Version": "2022-11-28"}
_URL_RE = re.compile(r"^https?://github\.com/(?P<owner>[A-Za-z0-9._-]+)/(?P<repo>[A-Za-z0-9._-]+?)(?:\.git)?(?:/tree/(?P<ref>[^/]+))?/?$")


class GitHubImportError(Exception):
    def __init__(self, message, status=422):
        super().__init__(message)
        self.status = status


def parse_github_url(url):
    """Return (owner, repo, ref_or_None). Rejects non-github.com hosts and lookalikes."""
    url = (url or "").strip()
    m = _URL_RE.match(url)
    if not m:
        raise GitHubImportError("Enter a public GitHub repository URL like https://github.com/owner/repository.")
    owner, repo = m.group("owner"), m.group("repo")
    if owner in (".", "..") or repo in (".", ".."):
        raise GitHubImportError("Invalid repository path.")
    return owner, repo, m.group("ref")


def _get(client, url):
    try:
        r = client.get(url)
    except httpx.HTTPError as exc:
        raise GitHubImportError(f"Could not reach GitHub ({type(exc).__name__}).", status=502) from exc
    if r.status_code == 404:
        raise GitHubImportError("Repository not found. It may be private or the URL may be wrong.", status=404)
    if r.status_code == 403 and "rate limit" in r.text.lower():
        raise GitHubImportError("GitHub rate limit reached. Please try again in a few minutes.", status=429)
    if r.status_code >= 400:
        raise GitHubImportError(f"GitHub returned HTTP {r.status_code}.", status=502)
    return r


def get_repo_meta(owner, repo):
    with httpx.Client(timeout=TIMEOUT, headers=HEADERS, follow_redirects=True) as client:
        data = _get(client, f"{API}/repos/{owner}/{repo}").json()
    if data.get("private"):
        raise GitHubImportError("Only public repositories can be imported.", status=422)
    return {
        "owner": owner, "repo": repo, "full_name": data.get("full_name", f"{owner}/{repo}"),
        "description": data.get("description"), "default_branch": data.get("default_branch", "main"),
        "is_public": not data.get("private", False), "html_url": data.get("html_url", f"https://github.com/{owner}/{repo}"),
    }


def list_branches(owner, repo):
    with httpx.Client(timeout=TIMEOUT, headers=HEADERS, follow_redirects=True) as client:
        rows = _get(client, f"{API}/repos/{owner}/{repo}/branches?per_page=100").json()
    return [{"name": b["name"], "commit": (b.get("commit") or {}).get("sha", "")[:40]} for b in rows if isinstance(b, dict)]


def resolve_ref_sha(owner, repo, ref):
    with httpx.Client(timeout=TIMEOUT, headers=HEADERS, follow_redirects=True) as client:
        data = _get(client, f"{API}/repos/{owner}/{repo}/commits/{ref}").json()
    return (data.get("sha") or "")[:40] or None


def download_zip(owner, repo, ref):
    """Download the branch archive to memory, capped at MAX_UPLOAD_MB. Returns bytes."""
    cap = get_settings().MAX_UPLOAD_MB * 1024 * 1024
    url = f"{CODELOAD}/{owner}/{repo}/zip/refs/heads/{ref}"
    buf = bytearray()
    with httpx.Client(timeout=TIMEOUT, headers={"User-Agent": HEADERS["User-Agent"]}, follow_redirects=True) as client:
        try:
            with client.stream("GET", url) as r:
                if r.status_code == 404:
                    raise GitHubImportError(f"Branch '{ref}' was not found in the repository.", status=404)
                if r.status_code >= 400:
                    raise GitHubImportError(f"Could not download the repository archive (HTTP {r.status_code}).", status=502)
                for chunk in r.iter_bytes():
                    buf.extend(chunk)
                    if len(buf) > cap:
                        raise GitHubImportError(f"Repository archive exceeds the {get_settings().MAX_UPLOAD_MB} MB limit.", status=422)
        except httpx.HTTPError as exc:
            raise GitHubImportError(f"Archive download failed ({type(exc).__name__}).", status=502) from exc
    if not buf.startswith(b"PK\x03\x04"):
        raise GitHubImportError("Downloaded archive is not a valid ZIP.", status=502)
    return bytes(buf)
