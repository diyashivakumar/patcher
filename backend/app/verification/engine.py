"""Proof-of-Fix engine: orchestrates isolated copies, the runner, and persistence.

The verdict comes from the runner's deterministic rules (testing/verdict.py) applied
to tests that actually executed. The backend never upgrades a verdict, and never
uses AI output in this path.
"""
import shutil
import tempfile
import time
from pathlib import Path

from app.models import Patch, Project, VerificationRun, VerificationTestResult
from app.models.audit_log import record
from app.models.base import utcnow
from app.services import storage
from app.verification import adapter

APPLIED_STATES = {"APPLIED", "VERIFIED", "REJECTED"}


class VerificationNotPossible(Exception):
    pass


def supported_scenarios(project: Project):
    if project.source_type != "fixture" or project.fixture_name not in storage.FIXTURES:
        return []
    return storage.FIXTURES[project.fixture_name]["verification_scenarios"]


def _require_scenario(project, scenario):
    scenarios = supported_scenarios(project)
    if not scenarios:
        raise VerificationNotPossible(
            "Verification runs only on bundled practice fixtures. Uploaded code is scanned and patched but "
            "never executed on this host."
        )
    if scenario not in scenarios:
        raise VerificationNotPossible(f"No executable tests for scenario '{scenario}' on this project")


def _copy_tree(src: Path, dest: Path):
    shutil.copytree(src, dest, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    return dest


def _summaries(raw):
    out = {}
    for name, phase in raw["phases"].items():
        out[name] = {
            "exploit_reproduced": phase.get("exploit_reproduced"),
            "load_error": phase.get("load_error"),
            "duration_ms": phase.get("duration_ms"),
            **{g: {k: phase[g][k] for k in ("total", "passed", "failed", "errors")}
               for g in ("security_tests", "regression_tests")},
        }
    return out


def _store_results(run, raw):
    position = 0
    for phase_name, phase in raw["phases"].items():
        for group in ("security_tests", "regression_tests"):
            for r in phase[group]["results"]:
                run.test_results.append(VerificationTestResult(
                    position=position, phase=phase_name, category=r.get("category", group.split("_")[0]),
                    test_id=r["test_id"], name=r.get("name", r["test_id"]), description=r.get("description", ""),
                    status=r["status"], expected=str(r.get("expected", "")), actual=str(r.get("actual", "")),
                    exploit_succeeded=r.get("exploit_succeeded"), evidence=r.get("evidence") or {},
                    privilege_map=r.get("privilege_map"),
                ))
                position += 1


def run_baseline(db, project: Project, scenario: str, actor="system"):
    """Attack Replay step 1: run the exploit + regression tests against the ORIGINAL code only."""
    _require_scenario(project, scenario)
    run = VerificationRun(project_id=project.id, kind="baseline", scenario=scenario, status="RUNNING",
                          started_at=utcnow(), verdict_reasons=[], phase_summaries={})
    started = time.perf_counter()
    with tempfile.TemporaryDirectory(prefix="patchproof-baseline-") as tmp:
        app_copy = _copy_tree(storage.original_dir(project.id), Path(tmp) / "original")
        try:
            raw = adapter.run_baseline(app_copy, scenario)
        except adapter.RunnerError as exc:
            raw = None
            run.status, run.error = "ERROR", str(exc)
    if raw:
        phase = raw["phases"]["baseline"]
        run.status = "COMPLETED"
        run.raw_output = raw
        run.phase_summaries = _summaries(raw)
        run.original_vulnerability_reproduced = bool(phase["exploit_reproduced"]) and not phase["load_error"]
        run.verdict_reasons = [
            "Original vulnerability reproduced: exploit succeeded against the unpatched code"
            if run.original_vulnerability_reproduced else
            "Exploit did not succeed against the current original code"
        ]
        _store_results(run, raw)
    run.completed_at = utcnow()
    run.duration_ms = int((time.perf_counter() - started) * 1000)
    db.add(run)
    db.flush()
    record(db, "verification.baseline", "verification_run", run.id, project.id, actor,
           scenario=scenario, status=run.status, reproduced=run.original_vulnerability_reproduced)
    return run


def run_proof_of_fix(db, patch: Patch, project: Project, actor="system"):
    """Original (pristine) vs. isolated copy of the patched working tree, then decide accept/reject."""
    if patch.status not in APPLIED_STATES:
        raise VerificationNotPossible(
            f"Patch is {patch.status}. It must be approved and applied before it can be verified."
        )
    scenario = patch.finding.vuln_type
    _require_scenario(project, scenario)

    run = VerificationRun(project_id=project.id, patch_id=patch.id, kind="proof_of_fix", scenario=scenario,
                          status="RUNNING", started_at=utcnow(), verdict_reasons=[], phase_summaries={})
    started = time.perf_counter()
    with tempfile.TemporaryDirectory(prefix="patchproof-verify-") as tmp:
        before = _copy_tree(storage.original_dir(project.id), Path(tmp) / "before")
        after = _copy_tree(storage.source_dir(project.id), Path(tmp) / "after")
        try:
            raw = adapter.run_compare(before, after, scenario)
        except adapter.RunnerError as exc:
            raw = None
            run.status, run.error = "ERROR", str(exc)
            run.verdict = "FAILED"
            run.verdict_reasons = [f"Verification could not be executed, so the patch is not validated: {exc}"]

    if raw:
        verdict = raw["verdict"]
        run.status = "COMPLETED"
        run.raw_output = raw
        run.phase_summaries = _summaries(raw)
        run.verdict = verdict["status"]
        run.verdict_reasons = list(verdict.get("reasons", []))
        run.original_vulnerability_reproduced = verdict.get("original_vulnerability_reproduced")
        run.exploit_blocked_after_patch = verdict.get("exploit_blocked_after_patch")
        run.regressions_pass_after_patch = verdict.get("regressions_pass_after_patch")
        _store_results(run, raw)
        # Accept/reject decision. PARTIALLY_VERIFIED leaves the patch APPLIED for human review.
        if run.verdict == "VERIFIED":
            patch.status = "VERIFIED"
        elif run.verdict == "FAILED":
            patch.status = "REJECTED"

    run.completed_at = utcnow()
    run.duration_ms = int((time.perf_counter() - started) * 1000)
    db.add(run)
    db.flush()
    record(db, "verification.proof_of_fix", "verification_run", run.id, project.id, actor,
           patch_id=str(patch.id), scenario=scenario, verdict=run.verdict, status=run.status)
    return run
