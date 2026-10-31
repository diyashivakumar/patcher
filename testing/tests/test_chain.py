"""Attack-chain scenario tests (real fixture execution, in-process via the Flask test client)."""
import json
import subprocess
import sys

from testing.harness import REPO_ROOT, fixture_client
from testing.runner import run_single
from testing.scenarios.chain import run_chain

FIX = REPO_ROOT / "fixtures"
VULN = FIX / "vulnerable_app"
SQLI_FIXED = FIX / "variants" / "patched_reference"   # SQLi (and IDOR) fixed


def _chain(path):
    with fixture_client(path) as c:
        return run_chain(c)


def test_unpatched_chain_reaches_final_and_ledger_shows_other_users():
    r = _chain(VULN)
    assert r["reached_final"] is True and r["steps_reached"] == 3
    assert r["chain_succeeded"] is True
    # Step 1 stole synthetic tokens; the walk exposed OTHER users' canary records only.
    assert any(s.startswith("api_token:") for s in r["stolen"])
    assert r["final_records"] and set(r["final_records"]) <= {"DOC-101", "DOC-202", "DOC-303"}
    for row in r["ledger"]:
        assert row["authorized"] is False and row["record_owner"] != row["actor"]


def test_sqli_fix_stops_chain_at_step_one_with_empty_ledger():
    r = _chain(SQLI_FIXED)
    assert r["reached_final"] is False and r["steps_reached"] == 1
    assert r["ledger"] == [] and r["final_records"] == []
    s1, s2, s3 = r["steps"]
    assert s1["reached"] is True and s1["succeeded"] is False   # UNION returns no token
    assert s2["reached"] is False and s3["reached"] is False


def test_chain_introduces_no_new_payload():
    # The only injection string the chain uses is the existing UNION step from scenarios/sqli.py.
    from testing.scenarios import chain, sqli
    import inspect as pyinspect
    assert chain.UNION_PAYLOAD in pyinspect.getsource(sqli._union)


def test_chain_runs_through_the_runner_phase_and_carries_its_ledger():
    report = run_single(VULN, "chain", "before_patch")
    assert report["scenario"] == "chain"
    results = report["phases"]["before_patch"]["security_tests"]["results"]
    assert len(results) == 1 and results[0]["exploit_succeeded"] is True
    chain = results[0]["evidence"]["chain"]
    assert chain["reached_final"] is True and chain["ledger"]


def test_chain_cli_scenario_choice():
    proc = subprocess.run([sys.executable, "-m", "testing.runner", "--scenario", "chain",
                           "--app-dir", str(VULN), "--phase", "before_patch"],
                          cwd=REPO_ROOT, capture_output=True, text=True, timeout=120)
    assert proc.returncode == 0, proc.stderr
    data = json.loads(proc.stdout)
    chain = data["phases"]["before_patch"]["security_tests"]["results"][0]["evidence"]["chain"]
    assert chain["steps_reached"] == 3
