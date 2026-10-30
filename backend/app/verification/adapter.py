"""Adapter for Dipto's independent test runner (python -m testing.runner).

The backend never imports the testing framework or re-implements its tests. It
runs the documented CLI in a subprocess and validates the JSON it writes
(see docs/testing_contract.md). The subprocess gets:
  * a minimal environment -- no DATABASE_URL, no other secrets
  * a hard timeout (VERIFICATION_TIMEOUT_SECONDS)
  * POSIX only: CPU-time and memory limits
The runner itself blocks outbound network connections and uses a throwaway SQLite DB.
"""
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

from app.config import REPO_ROOT, get_settings

SUPPORTED_SCHEMA = "1.0"
VERDICTS = {"VERIFIED", "PARTIALLY_VERIFIED", "FAILED"}


class RunnerError(Exception):
    pass


def _sandbox_env(tmp):
    env = {"PYTHONDONTWRITEBYTECODE": "1", "PYTHONNOUSERSITE": "1", "TEMP": tmp, "TMP": tmp, "TMPDIR": tmp}
    for key in ("PATH", "SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT"):
        if key in os.environ:
            env[key] = os.environ[key]
    return env


def _posix_limits(timeout):
    if sys.platform == "win32":
        return {}

    def limit():
        import resource
        resource.setrlimit(resource.RLIMIT_CPU, (timeout, timeout))
        resource.setrlimit(resource.RLIMIT_AS, (1024 * 1024 * 1024, 1024 * 1024 * 1024))

    return {"preexec_fn": limit}


def _invoke(args):
    settings = get_settings()
    timeout = settings.VERIFICATION_TIMEOUT_SECONDS
    with tempfile.TemporaryDirectory(prefix="patchproof-run-") as tmp:
        out = Path(tmp) / "result.json"
        cmd = [settings.TESTING_PYTHON, "-m", "testing.runner", *args, "--output", str(out)]
        try:
            proc = subprocess.run(cmd, cwd=REPO_ROOT, env=_sandbox_env(tmp), capture_output=True, text=True,
                                  timeout=timeout, **_posix_limits(timeout))
        except subprocess.TimeoutExpired as exc:
            raise RunnerError(f"Test runner exceeded the {timeout}s time limit") from exc
        except OSError as exc:
            raise RunnerError(f"Could not start test runner ({settings.TESTING_PYTHON}): {exc}") from exc
        if proc.returncode != 0 or not out.exists():
            tail = (proc.stderr or proc.stdout or "").strip()[-800:]
            raise RunnerError(f"Test runner exited with code {proc.returncode}: {tail}")
        try:
            data = json.loads(out.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise RunnerError("Test runner produced invalid JSON") from exc
    _validate(data)
    return data


def _validate(data):
    if not isinstance(data, dict) or data.get("schema_version") != SUPPORTED_SCHEMA:
        raise RunnerError(f"Unsupported runner output schema: {data.get('schema_version') if isinstance(data, dict) else None}")
    phases = data.get("phases")
    if not isinstance(phases, dict) or not phases:
        raise RunnerError("Runner output has no phases")
    for name, phase in phases.items():
        for group in ("security_tests", "regression_tests"):
            g = phase.get(group)
            if not isinstance(g, dict) or not isinstance(g.get("results"), list):
                raise RunnerError(f"Runner output phase '{name}' is missing {group}")
            for key in ("total", "passed", "failed", "errors"):
                if not isinstance(g.get(key), int):
                    raise RunnerError(f"Runner output phase '{name}'.{group}.{key} is not an integer")
            if g["total"] != len(g["results"]):
                raise RunnerError(f"Runner output phase '{name}'.{group} counts do not match its results")
    if data.get("mode") == "compare":
        if set(phases) != {"before_patch", "after_patch"}:
            raise RunnerError("Compare output must contain before_patch and after_patch")
        verdict = data.get("verdict") or {}
        if verdict.get("status") not in VERDICTS:
            raise RunnerError(f"Unknown verdict status: {verdict.get('status')}")


def run_compare(original_dir, patched_dir, scenario):
    return _invoke(["--scenario", scenario, "--original-dir", str(original_dir), "--patched-dir", str(patched_dir)])


def run_baseline(app_dir, scenario):
    return _invoke(["--scenario", scenario, "--app-dir", str(app_dir), "--phase", "baseline"])
