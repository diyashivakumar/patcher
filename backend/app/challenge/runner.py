"""Isolated execution runner for Fix Court candidates."""
import ast
import difflib
import shutil
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path

from app.challenge.forensics import scan_response_forensics
from app.challenge.gauntlet import run_idor_gauntlet, run_sqli_gauntlet
from app.challenge.schemas import CandidateOut, ForensicsEvidence, SafetyValidationResult
from app.challenge.validator import validate_candidate_ast
from app.challenge.verdict_engine import determine_fix_court_verdict
from app.config import REPO_ROOT
from testing.harness import fixture_client


def _find_function_span(file_text: str, func_name: str) -> tuple[int, int, str]:
    """Find line span [start_line, end_line] and original source of named function."""
    tree = ast.parse(file_text)
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == func_name:
            lines = file_text.splitlines(keepends=True)
            # 1-indexed lineno to end_lineno
            start = node.lineno
            end = node.end_lineno or node.lineno
            snippet = "".join(lines[start - 1:end])
            return start, end, snippet
    raise ValueError(f"Function '{func_name}' not found in source file.")


def _apply_replacement_function(file_text: str, func_name: str, replacement_code: str) -> tuple[str, str]:
    """Replace target function in file text and return (new_file_text, unified_diff)."""
    start, end, orig_snippet = _find_function_span(file_text, func_name)
    lines = file_text.splitlines(keepends=True)

    # Indentation adjustment: detect indentation of original def
    orig_def_line = lines[start - 1]
    indent = len(orig_def_line) - len(orig_def_line.lstrip())
    indent_prefix = " " * indent

    repl_lines = []
    for line in replacement_code.strip().splitlines():
        if line.strip():
            repl_lines.append(indent_prefix + line + "\n")
        else:
            repl_lines.append("\n")

    new_lines = lines[:start - 1] + repl_lines + lines[end:]
    new_text = "".join(new_lines)
    diff = "".join(difflib.unified_diff(
        orig_snippet.splitlines(keepends=True),
        repl_lines,
        fromfile=f"a/{func_name}",
        tofile=f"b/{func_name}",
    ))
    return new_text, diff


def evaluate_candidate(
    challenge_id: uuid.UUID,
    candidate_id: uuid.UUID,
    name: str,
    source_type: str,
    model_name: str | None,
    source_code: str,
    vuln_type: str,
    target_func_name: str,
    expected_args: list[str] | None,
    created_at: datetime | None = None,
) -> CandidateOut:
    """Safely validate, apply to an isolated copy, and evaluate a single candidate."""
    now = created_at or datetime.now(timezone.utc)
    vulnerable_fixture_dir = REPO_ROOT / "fixtures" / "vulnerable_app"
    orig_app_path = vulnerable_fixture_dir / "app.py"
    orig_text = orig_app_path.read_text(encoding="utf-8")

    # 1. AST Safety Validation
    safety = validate_candidate_ast(source_code, target_func_name, expected_args)

    if not safety.valid:
        verdict, rationale, convicting = determine_fix_court_verdict(safety, [], ForensicsEvidence(canary_detected=False))
        return CandidateOut(
            id=candidate_id,
            challenge_id=challenge_id,
            name=name,
            source_type=source_type,
            model_name=model_name,
            source_code=source_code,
            diff="",
            safety_status="REJECTED",
            safety_reason=safety.rejection_reason,
            verdict=verdict,
            verdict_rationale=rationale,
            convicting_test_id=convicting,
            security_passed=False,
            regression_passed=False,
            gauntlet_passed=False,
            forensics_clean=True,
            gauntlet_results=[],
            forensics_results=None,
            created_at=now,
        )

    # 2. Prepare Isolated Temp Working Copy
    diff = ""
    with tempfile.TemporaryDirectory(prefix="patchproof-court-") as tmp:
        tmp_dir = Path(tmp)
        # Copy original fixture files
        shutil.copytree(vulnerable_fixture_dir, tmp_dir / "app_copy")
        app_copy_dir = tmp_dir / "app_copy"
        app_file = app_copy_dir / "app.py"

        try:
            patched_text, diff = _apply_replacement_function(orig_text, target_func_name, source_code)
            # Verify patched file parses as valid Python
            ast.parse(patched_text)
            app_file.write_text(patched_text, encoding="utf-8")
        except Exception as exc:
            return CandidateOut(
                id=candidate_id,
                challenge_id=challenge_id,
                name=name,
                source_type=source_type,
                model_name=model_name,
                source_code=source_code,
                diff=diff,
                safety_status="REJECTED",
                safety_reason=f"Failed to apply replacement cleanly: {exc}",
                verdict="REJECTED_UNSAFE_CODE",
                verdict_rationale=f"Code could not be safely integrated into fixture: {exc}",
                convicting_test_id=None,
                security_passed=False,
                regression_passed=False,
                gauntlet_passed=False,
                forensics_clean=True,
                gauntlet_results=[],
                forensics_results=None,
                created_at=now,
            )

        # 3. Execute Gauntlet in Isolated Test Harness
        try:
            with fixture_client(app_copy_dir) as client:
                if vuln_type == "sqli":
                    results, bodies = run_sqli_gauntlet(client)
                else:
                    results, bodies = run_idor_gauntlet(client)
        except Exception as exc:
            return CandidateOut(
                id=candidate_id,
                challenge_id=challenge_id,
                name=name,
                source_type=source_type,
                model_name=model_name,
                source_code=source_code,
                diff=diff,
                safety_status="PASSED",
                safety_reason=None,
                verdict="INCONCLUSIVE",
                verdict_rationale=f"Execution error during test run: {exc}",
                convicting_test_id=None,
                security_passed=False,
                regression_passed=False,
                gauntlet_passed=False,
                forensics_clean=True,
                gauntlet_results=[],
                forensics_results=None,
                created_at=now,
            )

    # 4. Data Exposure Forensics
    forensics = scan_response_forensics(bodies)

    # 5. Authoritative Verdict
    verdict, rationale, convicting = determine_fix_court_verdict(safety, results, forensics)

    orig_tests = [t for t in results if t.category == "original_exploit"]
    variant_tests = [t for t in results if t.category == "variant_gauntlet"]
    regression_tests = [t for t in results if t.category == "regression"]

    return CandidateOut(
        id=candidate_id,
        challenge_id=challenge_id,
        name=name,
        source_type=source_type,
        model_name=model_name,
        source_code=source_code,
        diff=diff,
        safety_status="PASSED",
        safety_reason=None,
        verdict=verdict,
        verdict_rationale=rationale,
        convicting_test_id=convicting,
        security_passed=all(t.passed for t in orig_tests),
        regression_passed=all(t.passed for t in regression_tests),
        gauntlet_passed=all(t.passed for t in variant_tests),
        forensics_clean=not forensics.canary_detected,
        gauntlet_results=results,
        forensics_results=forensics,
        created_at=now,
    )
