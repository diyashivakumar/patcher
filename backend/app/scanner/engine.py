"""Scanner engine: walks a project directory and runs every detector on each Python file."""
import ast
from pathlib import Path

from app.scanner import idor, sqli

DETECTORS = (sqli.detect, idor.detect)
SKIP_DIRS = {".git", "__pycache__", "venv", ".venv", "node_modules", "site-packages", ".tox"}
MAX_FILE_BYTES = 1_000_000


def scan_source(text, rel_path):
    """Scan one file's text. Raises SyntaxError if it is not valid Python."""
    tree = ast.parse(text, filename=rel_path)
    lines = text.splitlines(keepends=True)
    findings = []
    for detect in DETECTORS:
        findings.extend(detect(tree, lines, rel_path))
    return findings


def scan_directory(root):
    """Return (findings, files_scanned, warnings) for every .py file under root."""
    root = Path(root)
    findings, warnings, files_scanned = [], [], 0
    for path in sorted(root.rglob("*.py")):
        rel = path.relative_to(root).as_posix()
        if any(part in SKIP_DIRS for part in path.relative_to(root).parts):
            continue
        if path.is_symlink() or path.stat().st_size > MAX_FILE_BYTES:
            warnings.append(f"Skipped {rel}: symlink or larger than {MAX_FILE_BYTES} bytes")
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            warnings.append(f"Skipped {rel}: not UTF-8 text")
            continue
        try:
            findings.extend(scan_source(text, rel))
        except SyntaxError as exc:
            warnings.append(f"Skipped {rel}: Python syntax error at line {exc.lineno}")
            continue
        files_scanned += 1
    return findings, files_scanned, warnings
