"""Apply and roll back patches on a project's working copy, with backups.

Files are read and written with newline="" so original line endings are preserved.
A patch is located at its recorded line numbers first; if other patches shifted the
lines, it falls back to a unique exact match of the snippet. Anything else is a conflict.
"""
import ast
import os
import shutil
from pathlib import Path

from app.services.storage import safe_join


class PatchConflict(Exception):
    pass


def read_source(path):
    with open(path, encoding="utf-8", newline="") as fh:
        return fh.read()


def _write_atomic(path, text):
    tmp = Path(str(path) + ".patchproof-tmp")
    with open(tmp, "w", encoding="utf-8", newline="") as fh:
        fh.write(text)
    os.replace(tmp, path)


def _locate(lines, snippet_lines, hint_line):
    n = len(snippet_lines)
    hint = hint_line - 1
    if lines[hint:hint + n] == snippet_lines:
        return hint
    matches = [i for i in range(len(lines) - n + 1) if lines[i:i + n] == snippet_lines]
    if len(matches) == 1:
        return matches[0]
    raise PatchConflict(
        "The code this patch expects is no longer present exactly once in the file "
        f"({len(matches)} matches). The file was changed after the patch was generated; regenerate the patch."
    )


def _swap(text, old_snippet, new_snippet, hint_line):
    lines = text.splitlines(keepends=True)
    old_lines = old_snippet.splitlines(keepends=True)
    at = _locate(lines, old_lines, hint_line)
    new_text = "".join(lines[:at] + new_snippet.splitlines(keepends=True) + lines[at + len(old_lines):])
    try:
        ast.parse(new_text)
    except SyntaxError as exc:
        raise PatchConflict(f"Result would not be valid Python (line {exc.lineno}: {exc.msg})") from exc
    return new_text


def check_applicable(source_root, patch):
    target = safe_join(source_root, patch.file_path)
    _swap(read_source(target), patch.original_snippet, patch.patched_snippet, patch.line_start)


def apply_patch(source_root, backup_root, patch):
    """Back up the target file, then apply. Returns the backup path (relative to backup_root)."""
    target = safe_join(source_root, patch.file_path)
    current = read_source(target)
    new_text = _swap(current, patch.original_snippet, patch.patched_snippet, patch.line_start)
    backup = safe_join(backup_root, f"{patch.id}/{patch.file_path}")
    backup.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(target, backup)
    _write_atomic(target, new_text)
    return backup.relative_to(Path(backup_root).resolve()).as_posix()


def rollback_patch(source_root, patch):
    """Reverse exactly this patch's change, leaving any other applied patches in place."""
    target = safe_join(source_root, patch.file_path)
    restored = _swap(read_source(target), patch.patched_snippet, patch.original_snippet, patch.line_start)
    _write_atomic(target, restored)
