"""Tests for the testing framework itself, run against the fixture and its reference variants."""
import json
import socket
import subprocess
import sys

import pytest

from testing.harness import REPO_ROOT, NetworkBlockedError, block_network
from testing.privilege_map import ALLOW, DENY, PRIVILEGE_MAP
from testing.runner import run_compare, run_phase

VULNERABLE = REPO_ROOT / "fixtures" / "vulnerable_app"
PATCHED = REPO_ROOT / "fixtures" / "variants" / "patched_reference"
OVER_RESTRICTIVE = REPO_ROOT / "fixtures" / "variants" / "over_restrictive"


def _by_id(phase):
    return {r["test_id"]: r for g in ("security_tests", "regression_tests") for r in phase[g]["results"]}


@pytest.mark.parametrize("scenario", ["sqli", "idor"])
def test_original_app_is_exploitable(scenario):
    phase = run_phase(VULNERABLE, scenario, "before_patch")
    assert phase["load_error"] is None
    assert phase["exploit_reproduced"] is True
    assert phase["security_tests"]["failed"] > 0


def test_sqli_exploit_evidence_shows_leaked_data():
    results = _by_id(run_phase(VULNERABLE, "sqli", "before_patch"))
    taut = results["sqli.tautology_leaks_private_docs"]
    assert taut["exploit_succeeded"] is True
    assert "Alice Private Diary" in taut["evidence"]["response"]["body_excerpt"]
    # The vulnerable query crashes on legitimate input containing a quote.
    assert results["sqli.search_with_apostrophe"]["status"] == "failed"


def test_idor_original_leaks_other_students_document():
    results = _by_id(run_phase(VULNERABLE, "idor", "before_patch"))
    assert results["idor.alice_reads_bob_doc"]["privilege_map"]["observed"] == ALLOW
    assert results["idor.alice_reads_own_doc"]["status"] == "passed"


@pytest.mark.parametrize("scenario", ["sqli", "idor", "all"])
def test_correct_patch_is_verified(scenario):
    report = run_compare(VULNERABLE, PATCHED, scenario)
    assert report["verdict"]["status"] == "VERIFIED", report["verdict"]["reasons"]
    after = report["phases"]["after_patch"]
    assert after["security_tests"]["failed"] == 0
    assert after["regression_tests"]["failed"] == 0


def test_over_restrictive_patch_is_rejected():
    report = run_compare(VULNERABLE, OVER_RESTRICTIVE, "idor")
    verdict = report["verdict"]
    assert verdict["status"] == "FAILED"
    assert verdict["exploit_blocked_after_patch"] is True      # it is "secure"...
    assert verdict["regressions_pass_after_patch"] is False    # ...but breaks legitimate users
    failing = {r["test_id"] for r in report["phases"]["after_patch"]["regression_tests"]["results"]
               if r["status"] == "failed"}
    assert "idor.alice_reads_own_doc" in failing
    assert "idor.teacher_reads_assigned_student_doc" in failing


def test_unpatched_copy_is_not_verified():
    report = run_compare(VULNERABLE, VULNERABLE, "sqli")
    assert report["verdict"]["status"] == "FAILED"


def test_broken_app_is_reported_not_crashed(tmp_path):
    (tmp_path / "app.py").write_text("def create_app(config):\n    raise RuntimeError('boom')\n")
    report = run_compare(VULNERABLE, tmp_path, "sqli")
    assert report["phases"]["after_patch"]["load_error"]
    assert report["verdict"]["status"] == "FAILED"


def test_privilege_map_covers_required_cases():
    pairs = {(r.actor, r.expected) for r in PRIVILEGE_MAP}
    assert ("alice", ALLOW) in pairs and ("alice", DENY) in pairs
    assert ("bob", DENY) in pairs and ("ms_rivera", ALLOW) in pairs and ("anonymous", DENY) in pairs


def test_network_is_blocked():
    block_network()
    with pytest.raises(NetworkBlockedError):
        socket.create_connection(("example.com", 80), timeout=1)


def test_cli_outputs_contract_json(tmp_path):
    out = tmp_path / "result.json"
    proc = subprocess.run(
        [sys.executable, "-m", "testing.runner", "--scenario", "idor",
         "--original-dir", str(VULNERABLE), "--patched-dir", str(PATCHED), "--output", str(out)],
        cwd=REPO_ROOT, capture_output=True, text=True, timeout=120,
    )
    assert proc.returncode == 0, proc.stderr
    data = json.loads(out.read_text())
    assert data["schema_version"] == "1.0"
    assert set(data["phases"]) == {"before_patch", "after_patch"}
    assert data["verdict"]["status"] == "VERIFIED"
