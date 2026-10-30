"""PatchProof test runner -- the stable interface between the testing framework and the backend.

Usage (run from the repository root):

  # One phase against one copy of the app
  python -m testing.runner --scenario sqli --app-dir fixtures/vulnerable_app --phase before_patch

  # Before/after comparison with a Proof-of-Fix verdict
  python -m testing.runner --scenario idor \
      --original-dir fixtures/vulnerable_app \
      --patched-dir fixtures/variants/patched_reference

  # Write JSON to a file instead of stdout
  python -m testing.runner --scenario all --app-dir fixtures/vulnerable_app --output result.json

Output format is documented in docs/testing_contract.md (schema_version 1.0).
Exit codes: 0 = run completed (read the JSON for results), 2 = bad arguments, 3 = internal error.
"""
import argparse
import json
import sys
import time
import traceback
from datetime import datetime, timezone
from pathlib import Path

from testing.harness import DEFAULT_SEED, block_network, fixture_client
from testing.scenarios import REGRESSION, SECURITY, get_tests
from testing.verdict import compute_verdict

SCHEMA_VERSION = "1.0"
PHASES = ("before_patch", "after_patch", "baseline")


def _empty_group():
    return {"total": 0, "passed": 0, "failed": 0, "errors": 0, "results": []}


def run_phase(app_dir, scenario, phase, seed_file=DEFAULT_SEED):
    started = time.perf_counter()
    result = {
        "phase": phase,
        "scenario": scenario,
        "app_dir": str(Path(app_dir).resolve()),
        "started_at": datetime.now(timezone.utc).isoformat(),
        "duration_ms": 0,
        "load_error": None,
        "exploit_reproduced": False,
        "security_tests": _empty_group(),
        "regression_tests": _empty_group(),
    }
    tests = get_tests(scenario)
    try:
        with fixture_client(app_dir, seed_file) as client:
            for test in tests:
                group = result["security_tests" if test.category == SECURITY else "regression_tests"]
                group["results"].append(_run_one(test, client))
    except Exception as exc:  # noqa: BLE001 - a broken patched app is a result, not a crash
        result["load_error"] = f"{type(exc).__name__}: {exc}"

    for key in ("security_tests", "regression_tests"):
        group = result[key]
        group["total"] = len(group["results"])
        group["passed"] = sum(r["status"] == "passed" for r in group["results"])
        group["failed"] = sum(r["status"] == "failed" for r in group["results"])
        group["errors"] = sum(r["status"] == "error" for r in group["results"])
    result["exploit_reproduced"] = any(
        r.get("exploit_succeeded") for r in result["security_tests"]["results"]
    )
    result["duration_ms"] = int((time.perf_counter() - started) * 1000)
    return result


def _run_one(test, client):
    base = {
        "test_id": test.test_id,
        "scenario": test.scenario,
        "category": test.category,
        "name": test.name,
        "description": test.description,
        "expected": test.expected,
    }
    try:
        outcome = test.run(client)
    except Exception as exc:  # noqa: BLE001
        return {**base, "status": "error", "actual": f"{type(exc).__name__}: {exc}",
                "exploit_succeeded": None, "evidence": {"traceback": traceback.format_exc()[-1500:]}}
    return {
        **base,
        "status": "passed" if outcome["passed"] else "failed",
        "actual": outcome["actual"],
        "exploit_succeeded": outcome.get("exploit_succeeded"),
        "evidence": outcome.get("evidence", {}),
        "privilege_map": outcome.get("privilege_map"),
    }


def run_compare(original_dir, patched_dir, scenario, seed_file=DEFAULT_SEED):
    before = run_phase(original_dir, scenario, "before_patch", seed_file)
    after = run_phase(patched_dir, scenario, "after_patch", seed_file)
    return {
        "schema_version": SCHEMA_VERSION,
        "mode": "compare",
        "scenario": scenario,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "phases": {"before_patch": before, "after_patch": after},
        "verdict": compute_verdict(before, after),
    }


def run_single(app_dir, scenario, phase, seed_file=DEFAULT_SEED):
    return {
        "schema_version": SCHEMA_VERSION,
        "mode": "phase",
        "scenario": scenario,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "phases": {phase: run_phase(app_dir, scenario, phase, seed_file)},
        "verdict": None,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(prog="python -m testing.runner", description=__doc__.split("\n")[0])
    parser.add_argument("--scenario", choices=["sqli", "idor", "all"], default="all")
    parser.add_argument("--app-dir", help="Single-phase mode: directory containing app.py")
    parser.add_argument("--phase", choices=PHASES, default="baseline")
    parser.add_argument("--original-dir", help="Compare mode: unpatched app directory")
    parser.add_argument("--patched-dir", help="Compare mode: patched app directory")
    parser.add_argument("--seed", default=str(DEFAULT_SEED), help="SQL seed file for the synthetic DB")
    parser.add_argument("--output", help="Write JSON here instead of stdout")
    args = parser.parse_args(argv)

    compare = bool(args.original_dir or args.patched_dir)
    if compare and not (args.original_dir and args.patched_dir):
        parser.error("compare mode needs both --original-dir and --patched-dir")
    if not compare and not args.app_dir:
        parser.error("provide --app-dir, or --original-dir and --patched-dir")

    block_network()
    try:
        if compare:
            report = run_compare(args.original_dir, args.patched_dir, args.scenario, args.seed)
        else:
            report = run_single(args.app_dir, args.scenario, args.phase, args.seed)
    except Exception:  # noqa: BLE001
        traceback.print_exc()
        return 3

    text = json.dumps(report, indent=2)
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
