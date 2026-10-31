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

SUPPORTED_SCHEMAS = {"1.0", "1.1"}  # 1.1 adds gauntlet + forensics
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


def _invoke(args, extra_variants=None):
    settings = get_settings()
    timeout = settings.VERIFICATION_TIMEOUT_SECONDS
    with tempfile.TemporaryDirectory(prefix="patchproof-run-") as tmp:
        out = Path(tmp) / "result.json"
        cmd = [settings.TESTING_PYTHON, "-m", "testing.runner", *args, "--output", str(out)]
        if extra_variants:
            extra_file = Path(tmp) / "extra_variants.json"
            extra_file.write_text(json.dumps(extra_variants), encoding="utf-8")
            cmd += ["--extra-variants", str(extra_file)]
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
    if not isinstance(data, dict) or data.get("schema_version") not in SUPPORTED_SCHEMAS:
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
        if data["schema_version"] == "1.1":
            g, f = data.get("gauntlet"), data.get("forensics")
            if not isinstance(g, dict) or not isinstance(g.get("cases"), list) or not isinstance(g.get("counts"), dict):
                raise RunnerError("Runner output 1.1 is missing a valid gauntlet section")
            if not isinstance(f, dict) or not isinstance(f.get("phases"), dict) or not isinstance(f.get("comparison"), dict):
                raise RunnerError("Runner output 1.1 is missing a valid forensics section")
            # Defence in depth (QA): counts must match the cases, and VERIFIED must not contradict the evidence.
            for status, n in g["counts"].items():
                if n != sum(c.get("status") == status for c in g["cases"]):
                    raise RunnerError(f"Runner gauntlet count for '{status}' does not match its cases")
            if verdict["status"] == "VERIFIED" and (g["counts"].get("bypass") or g["counts"].get("regression_failed")):
                raise RunnerError("Runner reported VERIFIED despite gauntlet bypasses or broken legitimate variants")


def run_compare(original_dir, patched_dir, scenario, extra_variants=None):
    return _invoke(["--scenario", scenario, "--original-dir", str(original_dir), "--patched-dir", str(patched_dir)],
                   extra_variants)


def run_baseline(app_dir, scenario, extra_variants=None):
    return _invoke(["--scenario", scenario, "--app-dir", str(app_dir), "--phase", "baseline"], extra_variants)


def run_chain(app_dir):
    """Run the composed `chain` scenario (one phase) and return its structured chain result.

    Reuses the same subprocess sandbox and validation as sqli/idor. The chain carries its own
    ledger in the single security test's evidence (see testing/scenarios/chain.py).
    """
    raw = run_baseline(app_dir, "chain")
    results = raw["phases"]["baseline"]["security_tests"]["results"]
    chain = results[0].get("evidence", {}).get("chain") if results else None
    if not isinstance(chain, dict) or "steps" not in chain or "ledger" not in chain:
        raise RunnerError("Runner did not return a chain result for scenario 'chain'")
    return chain
