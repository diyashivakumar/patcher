"""Exploit Variant Gauntlet + Data Exposure Forensics acceptance tests (real fixture execution)."""
import json
import subprocess
import sys

import pytest

from testing import gauntlet
from testing.canaries import CANARY_RECORDS
from testing.forensics import (INCONCLUSIVE, MULTIPLE_EXPOSED, NO_PROTECTED_DATA, PARTIAL_EXPOSURE, RECORD_EXPOSED,
                               REJECTED, inspect)
from testing.harness import REPO_ROOT
from testing.runner import run_compare, run_single

FIX = REPO_ROOT / "fixtures"
VULN, PATCHED = FIX / "vulnerable_app", FIX / "variants" / "patched_reference"
DENY_ALL, BLOCKLIST = FIX / "variants" / "over_restrictive", FIX / "variants" / "naive_blocklist"


def _cases(report):
    return {c["variant_id"]: c for c in report["gauntlet"]["cases"]}


# ------------------------------------------------------------------ canaries & inspection (unit)
def test_canary_markers_are_unique_and_synthetic():
    markers = [r.marker for r in CANARY_RECORDS] + [r.field_marker(f) for r in CANARY_RECORDS for f in r.fields]
    assert len(markers) == len(set(markers))
    assert all(m.startswith("CANARY-STUDENT-") for m in markers)


def test_status_code_alone_never_decides_exposure():
    marker_body = '{"title": "x [CANARY-STUDENT-B-202:TITLE]", "body": "y [CANARY-STUDENT-B-202:BODY]"}'
    assert inspect(marker_body, 403, "alice")["outcome"] == RECORD_EXPOSED       # 403 but data leaked
    assert inspect('{"title": "Algebra Notes"}', 200, "alice")["outcome"] == NO_PROTECTED_DATA  # 200, nothing leaked
    assert inspect("Forbidden", 403, "alice")["outcome"] == REJECTED
    assert inspect("Internal Server Error", 500, "alice")["outcome"] == INCONCLUSIVE


def test_partial_and_multiple_exposure_and_authorised_access():
    title_only = "[CANARY-STUDENT-B-202:TITLE]"
    r = inspect(title_only, 200, "alice")
    assert r["outcome"] == PARTIAL_EXPOSURE and r["records"][0]["exposed_fields"] == ["title"]
    two = "[CANARY-STUDENT-B-202:TITLE] [CANARY-STUDENT-C-303:TITLE]"
    assert inspect(two, 200, "alice")["outcome"] == MULTIPLE_EXPOSED
    own = "[CANARY-STUDENT-A-101:TITLE] [CANARY-STUDENT-A-101:BODY]"
    r = inspect(own, 200, "alice")
    assert r["outcome"] == NO_PROTECTED_DATA and r["records"][0]["authorized"] is True


# ------------------------------------------------------------------ variant validation / safety
def test_builtin_variants_pass_the_safety_allowlist():
    for v in gauntlet.BUILTIN["sqli"] + gauntlet.BUILTIN["idor"]:
        gauntlet.validate_variant(v)


@pytest.mark.parametrize("bad", [
    {"scenario": "sqli", "kind": "attack", "input": {"actor": "anonymous", "method": "GET", "path": "/search", "params": {"q": "'; DROP TABLE users; --"}}},
    {"scenario": "sqli", "kind": "attack", "input": {"actor": "anonymous", "method": "POST", "path": "/search", "params": {"q": "x"}}},
    {"scenario": "idor", "kind": "attack", "input": {"actor": "anonymous", "method": "GET", "path": "https://example.com/documents/1"}},
    {"scenario": "idor", "kind": "attack", "input": {"actor": "root", "method": "GET", "path": "/documents/1"}},
    {"scenario": "sqli", "kind": "attack", "input": {"actor": "anonymous", "method": "GET", "path": "/search", "params": {"q": "x", "debug": "1"}}},
    {"scenario": "sqli", "kind": "attack", "input": {"actor": "anonymous", "method": "GET", "path": "/search", "params": {"q": "' UPDATE documents SET body='' --"}}},
])
def test_unsafe_saved_variants_are_rejected(bad):
    with pytest.raises(ValueError):
        gauntlet.validate_variant(bad)


# ------------------------------------------------------------------ differential execution (real)
def test_sqli_reference_patch_blocks_all_valid_variants():
    report = run_compare(VULN, PATCHED, "sqli")
    cases = _cases(report)
    assert cases["sqli.gv.original"]["before"]["exploited"] is True          # original reproduces
    assert cases["sqli.gv.double_url_encoded"]["status"] == "invalid"         # not counted as a block
    assert report["gauntlet"]["counts"]["bypass"] == 0
    assert report["gauntlet"]["counts"]["blocked"] == report["gauntlet"]["valid_attack_variants"]
    assert report["verdict"]["status"] == "VERIFIED"


def test_naive_blocklist_bypasses_are_discovered():
    report = run_compare(VULN, BLOCKLIST, "sqli")
    cases = _cases(report)
    assert cases["sqli.gv.original"]["status"] == "blocked"       # the known payload IS blocked...
    for vid in ("sqli.gv.case", "sqli.gv.whitespace", "sqli.gv.inline_comment"):
        assert cases[vid]["status"] == "bypass", vid               # ...but variants survive
    assert report["verdict"]["status"] == "FAILED"
    assert report["verdict"]["exploit_blocked_after_patch"] is False
    assert report["forensics"]["comparison"]["records_still_exposed"]


def test_idor_ownership_patch_passes_gauntlet_and_privilege_map():
    report = run_compare(VULN, PATCHED, "idor")
    c = report["gauntlet"]["counts"]
    assert c["bypass"] == 0 and c["regression_failed"] == 0 and c["blocked"] > 0 and c["works"] == 4
    assert report["verdict"]["status"] == "VERIFIED"
    f = report["forensics"]
    assert "DOC-202" in f["phases"]["before_patch"]["unauthorized_records_exposed"]
    assert f["phases"]["after_patch"]["unauthorized_records_exposed"] == []
    assert set(f["comparison"]["legitimate_access_kept"]) == {"DOC-101", "DOC-202", "DOC-303"}


def test_deny_all_patch_is_not_rescued_by_the_gauntlet():
    report = run_compare(VULN, DENY_ALL, "idor")
    c = report["gauntlet"]["counts"]
    assert c["bypass"] == 0 and c["regression_failed"] == 4        # blocks attacks, breaks every legit case
    assert report["verdict"]["status"] == "FAILED"
    assert report["forensics"]["comparison"]["legitimate_access_lost"] == ["DOC-101", "DOC-202", "DOC-303"]


def test_sqli_exposure_is_limited_to_what_the_response_returned():
    phase = run_single(VULN, "sqli", "baseline")["phases"]["baseline"]
    by_id = {v["variant_id"]: v for v in phase["variants"]}
    taut = by_id["sqli.gv.original"]  # /search returns id + title only
    assert {e["record_id"] for e in taut["exposures"]} == {"DOC-101", "DOC-202", "DOC-303"}
    assert all(e["exposed_fields"] == ["title"] for e in taut["exposures"])
    assert taut["exposure_outcome"] == MULTIPLE_EXPOSED
    assert all(e["exposed_fields"] == ["body"] for e in by_id["sqli.gv.union_body"]["exposures"])


def test_evidence_never_stores_response_bodies():
    report = run_compare(VULN, PATCHED, "idor")
    text = json.dumps({"gauntlet": report["gauntlet"], "forensics": report["forensics"]})
    assert "Fabricated counselling notes" not in text   # body text never copied, only markers
    assert "tok-" not in text                           # no synthetic tokens either


def test_saved_regression_case_is_replayed_and_deduplicated(tmp_path):
    saved = [
        {"scenario": "sqli", "kind": "attack", "regression_case_id": "rc-1", "variation": "Saved: lower-case or",
         "input": {"actor": "anonymous", "method": "GET", "path": "/search", "params": {"q": "' or 1=1 --"}}},
        {"scenario": "sqli", "kind": "attack", "regression_case_id": "rc-2",  # identical to a built-in variant
         "input": {"actor": "anonymous", "method": "GET", "path": "/search", "params": {"q": "' oR 1=1 --"}}},
    ]
    report = run_compare(VULN, BLOCKLIST, "sqli", extra_variants=saved)
    cases = _cases(report)
    new = [c for c in cases.values() if c["source"] == "saved_regression_case"]
    assert len(new) == 1 and new[0]["status"] == "bypass" and new[0]["regression_case_id"] == "rc-1"
    assert cases["sqli.gv.case"]["regression_case_id"] == "rc-2"   # linked, not duplicated

    path = tmp_path / "extra.json"
    path.write_text(json.dumps(saved))
    out = tmp_path / "r.json"
    proc = subprocess.run([sys.executable, "-m", "testing.runner", "--scenario", "sqli", "--original-dir", str(VULN),
                           "--patched-dir", str(PATCHED), "--extra-variants", str(path), "--output", str(out)],
                          cwd=REPO_ROOT, capture_output=True, text=True, timeout=120)
    assert proc.returncode == 0, proc.stderr
    assert json.loads(out.read_text())["schema_version"] == "1.1"


def test_cli_rejects_unsafe_extra_variants(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text(json.dumps([{"scenario": "sqli", "kind": "attack",
                                 "input": {"actor": "anonymous", "method": "GET", "path": "/search", "params": {"q": "x; DROP TABLE users"}}}]))
    proc = subprocess.run([sys.executable, "-m", "testing.runner", "--scenario", "sqli", "--app-dir", str(VULN),
                           "--extra-variants", str(path)], cwd=REPO_ROOT, capture_output=True, text=True, timeout=60)
    assert proc.returncode == 2 and "invalid --extra-variants" in proc.stderr
