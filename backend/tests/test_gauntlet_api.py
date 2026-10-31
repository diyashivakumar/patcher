"""Gauntlet + Forensics through the real API (in-memory DB, real runner subprocess)."""


def _setup(client):
    project = client.post("/api/projects", json={"name": "Gauntlet", "fixture_name": "student_portal"}).json()
    scan = client.post("/api/scans", json={"project_id": project["id"]}).json()
    findings = {f["vuln_type"]: f for f in client.get(f"/api/scans/{scan['id']}/findings").json()}
    return project, findings


def _patch_and_verify(client, finding_id, strategy=None):
    patch = client.post("/api/patches/generate", json={"finding_id": finding_id, "strategy": strategy}).json()
    assert client.post(f"/api/patches/{patch['id']}/apply", json={"approved": True, "approved_by": "t"}).status_code == 200
    r = client.post("/api/verification/run", json={"patch_id": patch["id"]})
    assert r.status_code == 201, r.text
    return patch, r.json()


def test_naive_blocklist_bypasses_are_found_preserved_and_replayed(client):
    _, f = _setup(client)
    bad, run = _patch_and_verify(client, f["sqli"]["id"], "naive_blocklist_demo")
    g = run["gauntlet"]
    assert run["verdict"] == "FAILED" and run["exploit_blocked_after_patch"] is False
    assert g["counts"]["bypass"] >= 3 and "sqli.gv.case" in g["bypasses"]
    original = next(c for c in g["cases"] if c["variant_id"] == "sqli.gv.original")
    assert original["status"] == "blocked"                       # the known payload alone IS blocked
    assert any("bypass" in reason for reason in run["verdict_reasons"])
    assert run["forensics"]["comparison"]["records_still_exposed"] == ["DOC-101", "DOC-202", "DOC-303"]
    assert all(row["verification_run_id"] == run["id"]
               for row in run["forensics"]["phases"]["after_patch"]["ledger"])

    cases = client.get("/api/regression-cases?scenario=sqli").json()
    assert {c["source_variant_id"] for c in cases} == set(g["bypasses"])
    assert all(c["source_run_id"] == run["id"] and c["times_seen"] == 1 for c in cases)

    # Roll back, apply the correct fix: the preserved cases are replayed and now blocked.
    client.post(f"/api/patches/{bad['id']}/rollback", json={})
    _, good = _patch_and_verify(client, f["sqli"]["id"])
    assert good["verdict"] == "VERIFIED"
    linked = [c for c in good["gauntlet"]["cases"] if c["regression_case_id"]]
    assert {c["variant_id"] for c in linked} == set(g["bypasses"])
    assert all(c["status"] == "blocked" for c in linked)
    assert good["forensics"]["phases"]["after_patch"]["unauthorized_records_exposed"] == []
    assert len(client.get("/api/regression-cases").json()) == len(cases)  # no duplicates

    report = client.get(f"/api/reports/{run['id']}").json()
    assert report["gauntlet"]["counts"]["bypass"] == g["counts"]["bypass"]
    assert report["forensics"]["comparison"]["records_still_exposed"]
    html = client.get(f"/api/reports/{run['id']}?format=html").text
    assert "Exploit Variant Gauntlet" in html and "Data Exposure Forensics" in html and "BYPASS" in html
    assert "Fabricated counselling notes" not in html  # no response bodies copied into the report


def test_idor_forensics_before_and_after(client):
    _, f = _setup(client)
    bad, deny = _patch_and_verify(client, f["idor"]["id"], "deny_all_demo")
    assert deny["verdict"] == "FAILED" and deny["gauntlet"]["counts"]["regression_failed"] == 4
    assert deny["forensics"]["comparison"]["legitimate_access_lost"] == ["DOC-101", "DOC-202", "DOC-303"]
    client.post(f"/api/patches/{bad['id']}/rollback", json={})
    _, good = _patch_and_verify(client, f["idor"]["id"])
    fx = good["forensics"]
    assert good["verdict"] == "VERIFIED"
    assert "DOC-202" in fx["phases"]["before_patch"]["unauthorized_records_exposed"]
    assert fx["phases"]["after_patch"]["unauthorized_records_exposed"] == []
    assert fx["comparison"]["legitimate_access_kept"] == ["DOC-101", "DOC-202", "DOC-303"]
    a_reads_b = next(r for r in fx["phases"]["before_patch"]["ledger"]
                     if r["variant_id"] == "idor.gv.a_reads_b")
    assert a_reads_b["actor"] == "alice" and a_reads_b["record_owner"] == "bob"
    assert a_reads_b["exposed_fields"] == ["body", "title"] and "CANARY-STUDENT-B-202" in a_reads_b["canary_match"]


def test_baseline_run_records_forensics(client):
    project, _ = _setup(client)
    run = client.post("/api/verification/run", json={"project_id": project["id"], "scenario": "idor"}).json()
    assert run["gauntlet"] is None  # single-phase: no differential gauntlet
    assert "DOC-202" in run["forensics"]["phases"]["baseline"]["unauthorized_records_exposed"]
