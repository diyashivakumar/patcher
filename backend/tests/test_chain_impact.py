"""Kill-chain impact: breach bill (pure) + chain-impact matrix (real runner subprocess) + endpoint."""
from app.challenge import chain_impact
from app.reports import breach_bill


# ---------------------------------------------------------------- breach bill (pure)
def test_breach_bill_summarizes_ledger_and_categories():
    chain = {
        "stolen": ["api_token:alice", "api_token:bob"],
        "final_records": ["DOC-202", "DOC-303"],
        "ledger": [
            {"record_id": "DOC-202", "record_owner": "bob", "exposed_fields": ["body", "title"]},
            {"record_id": "DOC-303", "record_owner": "carol", "exposed_fields": ["title"]},
        ],
    }
    b = breach_bill.summarize(chain)
    assert b["records_exposed"] == 2 and b["records"] == ["DOC-202", "DOC-303"]
    assert b["fields_exposed"] == 3 and "DOC-202.body" in b["fields"]
    assert b["credentials_stolen"] == 2
    assert b["categories"]["identity"]["items"] == ["bob", "carol"]
    assert b["categories"]["private_content"]["count"] == 2
    assert b["any_exposure"] is True


def test_breach_bill_empty_ledger_is_not_an_exposure():
    b = breach_bill.summarize({"stolen": [], "final_records": [], "ledger": []})
    assert b["records_exposed"] == 0 and b["credentials_stolen"] == 0 and b["any_exposure"] is False


def test_every_penalty_figure_is_labelled_illustrative_maximum():
    b = breach_bill.summarize({"stolen": [], "ledger": []})
    assert b["penalty_caveat"] == "maximum statutory penalty — illustrative, not legal advice"
    assert b["dpdp_references"] and all(
        r["caveat"] == b["penalty_caveat"] and r["statutory_maximum_inr"] > 0 and r["statutory_maximum_label"]
        for r in b["dpdp_references"])
    # No figure is ever presented as a predicted or actual fine.
    blob = str(b).lower()
    assert "predicted" not in blob and "actual fine" not in blob and "estimated fine" not in blob


# ---------------------------------------------------------------- chain-impact matrix (real runner)
def test_chain_impact_matrix_against_four_copies():
    result = chain_impact.run_chain_impact(project=None)
    rows = {m["copy_id"]: m for m in result["matrix"]}
    assert set(rows) == {"original", "sqli_patched", "idor_patched", "both_patched"}
    assert result["total_steps"] == 3

    # Original: full chain, other users' records exposed.
    assert rows["original"]["reached_final"] is True and rows["original"]["chain_succeeded"] is True
    assert rows["original"]["breach_bill"]["records_exposed"] >= 1
    assert rows["original"]["breach_bill"]["credentials_stolen"] >= 1

    # SQLi fix: chain stops at step 1 (no token), nothing exposed.
    assert rows["sqli_patched"]["steps_reached"] == 1
    assert rows["sqli_patched"]["chain_succeeded"] is False
    assert rows["sqli_patched"]["breach_bill"]["any_exposure"] is False

    # IDOR fix: token still stolen, but the ownership check blocks the document walk.
    assert rows["idor_patched"]["steps_reached"] >= 2
    assert rows["idor_patched"]["chain_succeeded"] is False
    assert rows["idor_patched"]["breach_bill"]["records_exposed"] == 0

    # Both: fully blocked.
    assert rows["both_patched"]["chain_succeeded"] is False

    # Best single fix stops the chain earliest -> SQLi (reaches step 1 < IDOR's step 2+).
    assert result["best_single_fix"]["copy_id"] == "sqli_patched"
    assert result["best_single_fix"]["steps_reached"] == 1


def test_chain_impact_evidence_has_no_response_bodies():
    import json
    result = chain_impact.run_chain_impact(project=None)
    blob = json.dumps(result)
    assert "body_excerpt" not in blob               # per-step request/response evidence is dropped
    assert "Fabricated counselling notes" not in blob
    assert "tok-alice-SYNTHETIC" not in blob         # raw tokens never leave the runner


# ---------------------------------------------------------------- endpoint
def test_chain_impact_endpoint(client):
    r = client.post("/api/challenge/chain-impact", json={})
    assert r.status_code == 201, r.text
    data = r.json()
    assert data["best_single_fix"]["copy_id"] == "sqli_patched"
    original = next(m for m in data["matrix"] if m["copy_id"] == "original")
    assert original["reached_final"] is True
    assert original["breach_bill"]["dpdp_references"][0]["caveat"].startswith("maximum statutory penalty")


def test_chain_impact_endpoint_unknown_project(client):
    r = client.post("/api/challenge/chain-impact", json={"project_id": "00000000-0000-0000-0000-000000000000"})
    assert r.status_code == 404
