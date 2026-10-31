"""QA: edge cases of the authoritative verdict engine (testing/verdict.py), on synthetic inputs."""
import pytest

from testing.verdict import compute_verdict


def _group(passed=1, failed=0, errors=0):
    results = ([{"test_id": f"p{i}", "status": "passed"} for i in range(passed)]
               + [{"test_id": f"f{i}", "status": "failed"} for i in range(failed)]
               + [{"test_id": f"e{i}", "status": "error"} for i in range(errors)])
    return {"total": len(results), "passed": passed, "failed": failed, "errors": errors, "results": results}


def _phase(reproduced=False, sec=None, reg=None, load_error=None):
    return {"exploit_reproduced": reproduced, "load_error": load_error,
            "security_tests": sec or _group(), "regression_tests": reg or _group()}


def _gauntlet(**counts):
    base = {"blocked": 0, "bypass": 0, "invalid": 0, "inconclusive": 0, "works": 0, "regression_failed": 0, **counts}
    cases = [{"variant_id": f"{s}{i}", "status": s} for s, n in base.items() for i in range(n)]
    return {"counts": base, "cases": cases, "bypasses": [c["variant_id"] for c in cases if c["status"] == "bypass"]}


BEFORE = _phase(reproduced=True, sec=_group(passed=0, failed=2))
AFTER = _phase(sec=_group(2), reg=_group(3))


@pytest.mark.parametrize("label, before, after, gauntlet, expected", [
    ("all valid attacks blocked, legit ok", BEFORE, AFTER, _gauntlet(blocked=7, works=2, invalid=1), "VERIFIED"),
    ("one confirmed bypass", BEFORE, AFTER, _gauntlet(blocked=6, bypass=1, works=2), "FAILED"),
    ("attacks blocked but legit broken (deny-all)", BEFORE, AFTER, _gauntlet(blocked=9, regression_failed=4), "FAILED"),
    ("patched app errored on a variant", BEFORE, AFTER, _gauntlet(blocked=6, inconclusive=1, works=2), "PARTIALLY_VERIFIED"),
    ("original not reproduced", _phase(reproduced=False), AFTER, _gauntlet(blocked=7, works=2), "PARTIALLY_VERIFIED"),
    ("no security tests executed", BEFORE, _phase(sec={"total": 0, "passed": 0, "failed": 0, "errors": 0, "results": []}, reg=_group(3)), None, "FAILED"),
    ("no regression tests executed", BEFORE, _phase(sec=_group(2), reg={"total": 0, "passed": 0, "failed": 0, "errors": 0, "results": []}), None, "FAILED"),
    ("patched app failed to load", BEFORE, _phase(load_error="SyntaxError: boom"), _gauntlet(), "FAILED"),
    ("security test errored (partial failure)", BEFORE, _phase(sec=_group(1, errors=1), reg=_group(3)), None, "FAILED"),
    ("regression partially failing", BEFORE, _phase(sec=_group(2), reg=_group(2, failed=1)), _gauntlet(blocked=7, works=2), "FAILED"),
])
def test_verdict_edge_cases(label, before, after, gauntlet, expected):
    assert compute_verdict(before, after, gauntlet)["status"] == expected, label


def test_invalid_variants_never_count_as_blocks_or_failures():
    v = compute_verdict(BEFORE, AFTER, _gauntlet(blocked=1, invalid=9, works=1))
    assert v["status"] == "VERIFIED"
    assert any("1 valid exploit variant(s) blocked" in r and "9 invalid" in r for r in v["reasons"])


def test_bypass_forces_exploit_blocked_false_even_if_classic_tests_pass():
    v = compute_verdict(BEFORE, AFTER, _gauntlet(blocked=6, bypass=1))
    assert v["exploit_blocked_after_patch"] is False and v["gauntlet_bypasses"] == 1


def test_inconclusive_can_never_produce_verified():
    for n in range(1, 4):
        assert compute_verdict(BEFORE, AFTER, _gauntlet(blocked=5, inconclusive=n, works=2))["status"] != "VERIFIED"
