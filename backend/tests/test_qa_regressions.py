"""Backend regression tests for defects found during final QA (docs/FINAL_QA_REPORT.md)."""
import copy

import pytest

from app.config import REPO_ROOT, get_settings
from app.verification import adapter

VULN = REPO_ROOT / "fixtures" / "vulnerable_app"


def _apply(client, patch_id, who):
    return client.post(f"/api/patches/{patch_id}/apply", json={"approved": True, "approved_by": who})


def _sqli_patch(client, strategy=None):
    project = client.post("/api/projects", json={"name": "QA", "fixture_name": "student_portal"}).json()
    scan = client.post("/api/scans", json={"project_id": project["id"]}).json()
    finding = next(f for f in client.get(f"/api/scans/{scan['id']}/findings").json() if f["vuln_type"] == "sqli")
    return client.post("/api/patches/generate", json={"finding_id": finding["id"], "strategy": strategy}).json()


# QA-5 (low): a whitespace-only approver was accepted into the audit trail.
def test_whitespace_only_approver_is_rejected(client):
    patch = _sqli_patch(client)
    r = _apply(client, patch["id"], "   ")
    assert r.status_code == 422 and r.json()["error"]["code"] == "validation_error"
    assert client.get(f"/api/patches/{patch['id']}").json()["status"] == "PROPOSED"
    r = _apply(client, patch["id"], "  Diya  ")
    assert r.status_code == 200 and r.json()["approved_by"] == "Diya"


# QA-6 (defence in depth): the backend must refuse runner output whose verdict contradicts its own evidence.
def _real_compare_output():
    return adapter.run_compare(VULN, REPO_ROOT / "fixtures" / "variants" / "patched_reference", "sqli")


def test_adapter_accepts_consistent_runner_output():
    data = _real_compare_output()
    assert data["verdict"]["status"] == "VERIFIED"
    adapter._validate(data)


def test_adapter_rejects_verified_with_bypass():
    data = copy.deepcopy(_real_compare_output())
    case = next(c for c in data["gauntlet"]["cases"] if c["status"] == "blocked")
    case["status"] = "bypass"
    data["gauntlet"]["counts"]["blocked"] -= 1
    data["gauntlet"]["counts"]["bypass"] += 1
    with pytest.raises(adapter.RunnerError, match="VERIFIED despite"):
        adapter._validate(data)


def test_adapter_rejects_counts_that_do_not_match_cases():
    data = copy.deepcopy(_real_compare_output())
    data["gauntlet"]["counts"]["blocked"] += 3
    with pytest.raises(adapter.RunnerError, match="does not match"):
        adapter._validate(data)


# QA-9 (medium, demo-facing): the dashboard counted findings whose patch was VERIFIED as "open".
def test_dashboard_open_findings_exclude_verified_patches(client):
    patch = _sqli_patch(client)
    assert client.get("/api/dashboard/summary").json()["open_findings"] == 2      # sqli + idor
    _apply(client, patch["id"], "qa")
    run = client.post("/api/verification/run", json={"patch_id": patch["id"]}).json()
    assert run["verdict"] == "VERIFIED"
    summary = client.get("/api/dashboard/summary").json()
    assert summary["open_findings"] == 1 and summary["open_findings_by_severity"]["CRITICAL"] == 0


# QA-7: a hanging patched app must end as a runner error (-> FAILED), never hang the API.
def test_hanging_app_hits_the_timeout(tmp_path, monkeypatch):
    (tmp_path / "app.py").write_text("import time\ndef create_app(config):\n    time.sleep(30)\n")
    monkeypatch.setattr(get_settings(), "VERIFICATION_TIMEOUT_SECONDS", 3)
    with pytest.raises(adapter.RunnerError, match="time limit"):
        adapter.run_compare(VULN, tmp_path, "sqli")


# QA-8: a preserved bypass must keep its oracle, or replaying it could not detect the bypass again.
def test_preserved_bypass_keeps_probe_oracle(client):
    patch = _sqli_patch(client, "naive_blocklist_demo")
    _apply(client, patch["id"], "qa")
    run = client.post("/api/verification/run", json={"patch_id": patch["id"]}).json()
    assert run["verdict"] == "FAILED"
    saved = {c["source_variant_id"]: c for c in client.get("/api/regression-cases?scenario=sqli").json()}
    assert saved["sqli.gv.union_probe"]["check"] == {"type": "union_marker", "marker": "PPROOF-PROBE-UNION"}
    replay = next(c for c in run["gauntlet"]["cases"] if c["variant_id"] == "sqli.gv.union_probe")
    assert replay["check"] == {"type": "union_marker", "marker": "PPROOF-PROBE-UNION"}
