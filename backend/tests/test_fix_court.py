"""Tests for Fix Court: Safety AST validator, Gauntlet, Forensics, Verdict precedence, and API."""
import uuid
import pytest
from app.challenge.validator import validate_candidate_ast
from app.challenge.forensics import scan_response_forensics
from app.challenge.verdict_engine import determine_fix_court_verdict
from app.challenge.schemas import ForensicsEvidence, GauntletTestEvidence, SafetyValidationResult
from app.challenge.service import run_challenge_trial, submit_judge_replacement


def test_safety_validator_blocks_forbidden_imports():
    bad_code = """
def search():
    import os
    os.system("whoami")
    return []
"""
    result = validate_candidate_ast(bad_code, "search")
    assert not result.valid
    assert "Forbidden import" in result.rejection_reason


def test_safety_validator_blocks_forbidden_calls():
    bad_code = """
def search():
    eval("__import__('os').system('id')")
    return []
"""
    result = validate_candidate_ast(bad_code, "search")
    assert not result.valid
    assert "Forbidden function call 'eval'" in result.rejection_reason


def test_safety_validator_approves_safe_flask_function():
    safe_code = """
def search():
    term = request.args.get('q', '')
    rows = get_db().execute('SELECT id, title FROM documents WHERE is_public = 1 AND title LIKE ?', (f'%{term}%',)).fetchall()
    return jsonify([dict(r) for r in rows])
"""
    result = validate_candidate_ast(safe_code, "search")
    assert result.valid


def test_forensics_detects_canary_markers():
    leaky_bodies = [
        '{"id": 1, "body": "Normal document"}',
        '{"id": 2, "secret": "SYNTHETIC-PRIVATE-ALICE-DATA-KEY"}',
    ]
    forensics = scan_response_forensics(leaky_bodies)
    assert forensics.canary_detected
    assert len(forensics.detected_markers) > 0


def test_verdict_precedence_safety_first():
    safety_fail = SafetyValidationResult(valid=False, rejection_reason="Dangerous eval")
    verdict, rationale, _ = determine_fix_court_verdict(safety_fail, [], ForensicsEvidence(canary_detected=False))
    assert verdict == "REJECTED_UNSAFE_CODE"


def test_verdict_precedence_canary_leak():
    safety_ok = SafetyValidationResult(valid=True)
    tests = [
        GauntletTestEvidence(payload_id="orig", name="orig", payload="1", category="original_exploit", expected="", actual="", passed=True),
    ]
    leaky_forensics = ForensicsEvidence(canary_detected=True, detected_markers=["SYNTHETIC-CANARY"])
    verdict, _, _ = determine_fix_court_verdict(safety_ok, tests, leaky_forensics)
    assert verdict == "DATA_LEAK"


def test_fix_court_trial_cached_sqli():
    dummy_fid = uuid.uuid4()
    trial = run_challenge_trial(finding_id=dummy_fid, count=6, use_cache=True)
    assert trial.total_candidates == 6
    assert len(trial.candidates) == 6
    # Scoreboard format "X / N GENUINE"
    assert "GENUINE" in trial.scoreboard
    assert trial.verdict_counts["GENUINE"] >= 1


def test_fix_court_api_endpoints(client):
    # 1. Findings
    res = client.get("/api/challenge/findings")
    assert res.status_code == 200
    findings = res.json()
    assert len(findings) >= 2
    fid = findings[0]["id"]

    # 2. Run trial
    run_res = client.post("/api/challenge/run", json={"finding_id": fid, "count": 4, "use_cache": True})
    assert run_res.status_code == 200
    trial_data = run_res.json()
    assert trial_data["total_candidates"] == 4
    chal_id = trial_data["id"]

    # 3. Retrieve trial
    get_res = client.get(f"/api/challenge/{chal_id}")
    assert get_res.status_code == 200

    # 4. Judge submit
    judge_res = client.post(
        "/api/challenge/submit",
        json={
            "finding_id": fid,
            "source_code": "def search():\n    return jsonify([])\n",
            "candidate_name": "Test Mock Fix",
        },
    )
    assert judge_res.status_code == 200
    assert judge_res.json()["verdict"] in [
        "GENUINE",
        "OVER_RESTRICTIVE",
        "FAKE_FIX",
        "BYPASSED",
        "DATA_LEAK",
        "REJECTED_UNSAFE_CODE",
    ]
