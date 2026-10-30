"""End-to-end API flow. Verification really executes the testing runner in a subprocess."""
import io
import zipfile

from app.services import storage


def _create_fixture_project(client):
    r = client.post("/api/projects", json={"name": "Demo portal", "fixture_name": "student_portal"})
    assert r.status_code == 201, r.text
    return r.json()


def _scan(client, project_id):
    r = client.post("/api/scans", json={"project_id": project_id})
    assert r.status_code == 201, r.text
    scan = r.json()
    findings = client.get(f"/api/scans/{scan['id']}/findings").json()
    return scan, {f["vuln_type"]: f for f in findings}


def _apply(client, patch_id):
    r = client.post(f"/api/patches/{patch_id}/apply", json={"approved": True, "approved_by": "diya"})
    assert r.status_code == 200, r.text
    return r.json()


def _verify(client, patch_id):
    r = client.post("/api/verification/run", json={"patch_id": patch_id})
    assert r.status_code == 201, r.text
    return r.json()


def test_health_and_ollama_unavailable(client):
    assert client.get("/api/health").json()["database"] == "ok"
    ollama = client.get("/api/health/ollama").json()
    assert ollama["available"] is False and "without it" in ollama["message"]


def test_full_sqli_proof_of_fix(client):
    project = _create_fixture_project(client)
    assert project["verification_supported"] is True
    scan, findings = _scan(client, project["id"])
    assert scan["findings_count"] == 2 and scan["severity_counts"]["CRITICAL"] == 1

    # Baseline: the original exploit reproduces.
    base = client.post("/api/verification/run", json={"project_id": project["id"], "scenario": "sqli"}).json()
    assert base["kind"] == "baseline" and base["original_vulnerability_reproduced"] is True

    patch = client.post("/api/patches/generate", json={"finding_id": findings["sqli"]["id"]}).json()
    assert patch["status"] == "PROPOSED" and "LIKE ?" in patch["diff"]

    # Verification before approval is refused.
    r = client.post("/api/verification/run", json={"patch_id": patch["id"]})
    assert r.status_code == 409 and r.json()["error"]["code"] == "verification_not_possible"
    # Apply without approval is refused.
    r = client.post(f"/api/patches/{patch['id']}/apply", json={"approved": False, "approved_by": "x"})
    assert r.status_code == 403

    _apply(client, patch["id"])
    run = _verify(client, patch["id"])
    assert run["verdict"] == "VERIFIED", run["verdict_reasons"]
    assert run["original_vulnerability_reproduced"] and run["exploit_blocked_after_patch"]
    phases = {t["phase"] for t in run["test_results"]}
    assert phases == {"before_patch", "after_patch"}
    assert client.get(f"/api/patches/{patch['id']}").json()["status"] == "VERIFIED"

    # Re-scan reflects the applied patch.
    _, after = _scan(client, project["id"])
    assert set(after) == {"idor"}

    report = client.get(f"/api/reports/{run['id']}").json()
    assert report["verification"]["verdict"] == "VERIFIED" and report["patch"]["diff"]
    html = client.get(f"/api/reports/{run['id']}?format=html")
    assert html.status_code == 200 and "VERIFIED" in html.text and "<script" not in html.text


def test_over_restrictive_patch_rejected_then_rollback_and_fix(client):
    project = _create_fixture_project(client)
    _, findings = _scan(client, project["id"])
    idor_id = findings["idor"]["id"]

    bad = client.post("/api/patches/generate", json={"finding_id": idor_id, "strategy": "deny_all_demo"}).json()
    assert bad["is_demo_bad_patch"] is True
    _apply(client, bad["id"])
    run = _verify(client, bad["id"])
    assert run["verdict"] == "FAILED"
    assert run["exploit_blocked_after_patch"] is True and run["regressions_pass_after_patch"] is False
    failing = {t["test_id"] for t in run["test_results"] if t["phase"] == "after_patch" and t["status"] == "failed"}
    assert "idor.alice_reads_own_doc" in failing
    assert client.get(f"/api/patches/{bad['id']}").json()["status"] == "REJECTED"

    # Cannot stack a new patch on top of the rejected one.
    r = client.post("/api/patches/generate", json={"finding_id": idor_id})
    assert r.status_code == 409 and r.json()["error"]["code"] == "patch_already_applied"

    rb = client.post(f"/api/patches/{bad['id']}/rollback", json={"reason": "rejected by Proof-of-Fix"})
    assert rb.status_code == 200 and rb.json()["status"] == "ROLLED_BACK"
    source = (storage.source_dir(project["id"]) / "app.py").read_text()
    original = (storage.original_dir(project["id"]) / "app.py").read_text()
    assert source == original

    good = client.post("/api/patches/generate", json={"finding_id": idor_id}).json()
    _apply(client, good["id"])
    run = _verify(client, good["id"])
    assert run["verdict"] == "VERIFIED", run["verdict_reasons"]
    pm = [t["privilege_map"] for t in run["test_results"] if t["phase"] == "after_patch" and t["privilege_map"]]
    assert all(p["expected"] == p["observed"] for p in pm) and len(pm) == 7

    summary = client.get("/api/dashboard/summary").json()
    # The rejected patch was rolled back, so it now counts as ROLLED_BACK; its FAILED run stays on record.
    assert summary["patches_verified"] == 1 and summary["patches_rejected"] == 0
    assert summary["verification_runs_by_verdict"] == {"VERIFIED": 1, "PARTIALLY_VERIFIED": 0, "FAILED": 1}


def test_both_patches_applied_together(client):
    project = _create_fixture_project(client)
    _, findings = _scan(client, project["id"])
    p1 = client.post("/api/patches/generate", json={"finding_id": findings["idor"]["id"]}).json()
    p2 = client.post("/api/patches/generate", json={"finding_id": findings["sqli"]["id"]}).json()
    _apply(client, p1["id"])
    _apply(client, p2["id"])  # line numbers unchanged above the IDOR insert; still applies cleanly
    assert _verify(client, p1["id"])["verdict"] == "VERIFIED"
    assert _verify(client, p2["id"])["verdict"] == "VERIFIED"
    # Rolling back only the SQLi patch leaves the IDOR fix in place.
    client.post(f"/api/patches/{p2['id']}/rollback", json={})
    source = (storage.source_dir(project["id"]) / "app.py").read_text()
    assert "can_view_document(user, doc):\n            abort(403)" in source and "LIKE '%{term}%'" in source


def test_upload_is_scanned_but_never_verified(client):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("svc/db.py", 'def find(cur, name):\n    cur.execute(f"SELECT * FROM u WHERE n = \'{name}\'")\n')
        zf.writestr("svc/.env", "DATABASE_URL=secret")
    r = client.post("/api/projects/upload", data={"name": "Uploaded"},
                    files={"file": ("code.zip", buf.getvalue(), "application/zip")})
    assert r.status_code == 201, r.text
    project = r.json()
    assert project["source_type"] == "upload" and project["verification_supported"] is False
    assert any(s["path"] == "svc/.env" for s in project["upload_skipped"])
    _, findings = _scan(client, project["id"])
    patch = client.post("/api/patches/generate", json={"finding_id": findings["sqli"]["id"]}).json()
    assert "?" in patch["patched_snippet"] and "(name,)" in patch["patched_snippet"]
    _apply(client, patch["id"])
    r = client.post("/api/verification/run", json={"patch_id": patch["id"]})
    assert r.status_code == 409 and "never executed" in r.json()["error"]["message"]


def test_upload_traversal_rejected_via_api(client):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("../../evil.py", "x")
    r = client.post("/api/projects/upload", data={"name": "Bad"},
                    files={"file": ("bad.zip", buf.getvalue(), "application/zip")})
    assert r.status_code == 422 and r.json()["error"]["code"] == "upload_rejected"


def test_error_format(client):
    r = client.get("/api/projects/00000000-0000-0000-0000-000000000000")
    assert r.status_code == 404 and r.json() == {"error": {"code": "not_found", "message": "Project not found",
                                                           "details": None}}
    r = client.post("/api/verification/run", json={})
    assert r.status_code == 422 and r.json()["error"]["code"] == "validation_error"
