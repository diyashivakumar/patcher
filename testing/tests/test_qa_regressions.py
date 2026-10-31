"""Regression tests for defects found during final QA (docs/FINAL_QA_REPORT.md).

Each test reproduces a way PatchProof could previously claim a vulnerable app was securely patched,
or a safety-boundary gap, and asserts the corrected behaviour.
"""
import socket

import pytest

from testing import gauntlet
from testing.harness import REPO_ROOT, NetworkBlockedError, block_network
from testing.runner import run_compare

FIX = REPO_ROOT / "fixtures"
VULN = FIX / "vulnerable_app"
PATCHED = FIX / "variants" / "patched_reference"


def _cases(report):
    return {c["variant_id"]: c for c in report["gauntlet"]["cases"]}


# QA-1 (critical): output filtering is not a fix -- injection must be detected by execution probes.
def test_output_filter_sqli_patch_is_rejected():
    report = run_compare(VULN, FIX / "variants" / "output_filter", "sqli")
    cases = _cases(report)
    assert cases["sqli.gv.union_probe"]["status"] == "bypass"
    assert cases["sqli.gv.boolean_probe"]["status"] == "bypass"
    assert cases["sqli.gv.union_probe"]["after"]["injection_probe_hit"] is True
    assert report["verdict"]["status"] == "FAILED"
    assert report["verdict"]["exploit_blocked_after_patch"] is False


# QA-2 (critical): encoding/"redacting" fields while still serving the record is still exposure.
def test_encoded_idor_patch_is_rejected_with_identity_evidence():
    report = run_compare(VULN, FIX / "variants" / "idor_encoded", "idor")
    case = _cases(report)["idor.gv.a_reads_b"]
    assert case["status"] == "bypass"
    rec = next(r for r in case["after"]["records"] if r["record_id"] == "DOC-202")
    assert rec["detection"] == "record_identity" and rec["authorized"] is False
    assert set(rec["exposed_fields"]) == {"title", "body"}
    assert report["verdict"]["status"] == "FAILED"
    assert "DOC-202" in report["forensics"]["comparison"]["records_still_exposed"]


def test_probes_are_valid_on_original_and_blocked_by_real_fix():
    cases = _cases(run_compare(VULN, PATCHED, "sqli"))
    for vid in ("sqli.gv.union_probe", "sqli.gv.boolean_probe"):
        assert cases[vid]["before"]["injection_probe_hit"] is True, vid   # the probe really proves execution
        assert cases[vid]["status"] == "blocked", vid
        assert "did not execute" in cases[vid]["reason"]


def test_identity_oracle_does_not_flag_authorised_or_denied_requests():
    cases = _cases(run_compare(VULN, PATCHED, "idor"))
    assert all(c["status"] in ("blocked", "works") for c in cases.values())
    own = cases["idor.gv.legit_a_own"]["after"]["records"]
    assert own and all(r["authorized"] for r in own)


# QA-3 (medium): the in-process network guard missed connect_ex / sendto / DNS.
@pytest.mark.parametrize("call", [
    lambda: socket.socket().connect_ex(("192.0.2.1", 9)),
    lambda: socket.socket(socket.AF_INET, socket.SOCK_DGRAM).sendto(b"x", ("192.0.2.1", 9)),
    lambda: socket.getaddrinfo("example.com", 80),
    lambda: socket.gethostbyname("example.com"),
])
def test_network_guard_covers_all_ip_entry_points(call):
    block_network()
    with pytest.raises(NetworkBlockedError):
        call()


# QA-4 (low): raw_query allowlist only checked the "q=" prefix.
@pytest.mark.parametrize("raw", ["q=x&admin=1", "q=a&q=b", "admin=1"])
def test_raw_query_must_be_exactly_one_q(raw):
    with pytest.raises(ValueError):
        gauntlet.validate_variant({"scenario": "sqli", "kind": "attack",
                                   "input": {"actor": "anonymous", "method": "GET", "path": "/search", "raw_query": raw}})


def test_single_q_raw_query_still_allowed():
    gauntlet.validate_variant({"scenario": "sqli", "kind": "attack",
                               "input": {"actor": "anonymous", "method": "GET", "path": "/search", "raw_query": "q=%27x"}})


@pytest.mark.parametrize("check", [
    {"type": "union_marker", "marker": "<script>"},
    {"type": "rows_with_ids", "ids": ["1"]},
    {"type": "public_titles", "titles": ["x"]},   # legit-only check on an attack
    {"type": "exec", "cmd": "ls"},
])
def test_attack_oracles_are_allowlisted(check):
    with pytest.raises(ValueError):
        gauntlet.validate_variant({"scenario": "sqli", "kind": "attack", "check": check,
                                   "input": {"actor": "anonymous", "method": "GET", "path": "/search", "params": {"q": "x"}}})


def test_saved_case_keeps_its_probe_oracle():
    saved = [{"scenario": "sqli", "kind": "attack", "regression_case_id": "rc-probe",
              "check": {"type": "union_marker", "marker": "PPROOF-PROBE-SAVED"},
              "input": {"actor": "anonymous", "method": "GET", "path": "/search",
                        "params": {"q": "' UNION SELECT 7, 'PPROOF-PROBE-SAVED' --"}}}]
    cases = _cases(run_compare(VULN, FIX / "variants" / "output_filter", "sqli", extra_variants=saved))
    saved_case = next(c for c in cases.values() if c["regression_case_id"] == "rc-probe")
    assert saved_case["status"] == "bypass" and saved_case["check"]["type"] == "union_marker"
