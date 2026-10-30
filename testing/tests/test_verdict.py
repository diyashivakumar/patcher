"""Exercise verdict decisions independently of fixture loading and exploits."""

import pytest

from testing.verdict import compute_verdict


def _group(category, statuses):
    return {
        "total": len(statuses),
        "passed": statuses.count("passed"),
        "failed": statuses.count("failed"),
        "errors": statuses.count("error"),
        "results": [
            {"test_id": f"idor.{category}_{index}", "status": status}
            for index, status in enumerate(statuses)
        ],
    }


def _phase(*, reproduced=False, security=("passed",), regression=("passed",)):
    return {
        "load_error": None,
        "exploit_reproduced": reproduced,
        "security_tests": _group("security", security),
        "regression_tests": _group("regression", regression),
    }


@pytest.mark.parametrize(
    "reproduced, expected",
    [(True, "VERIFIED"), (False, "PARTIALLY_VERIFIED")],
)
def test_passing_patch_requires_original_exploit_for_full_verification(reproduced, expected):
    before = _phase(reproduced=reproduced)
    verdict = compute_verdict(before, _phase())
    assert verdict["status"] == expected
    assert verdict["original_vulnerability_reproduced"] is reproduced
    assert verdict["exploit_blocked_after_patch"] is True
    assert verdict["regressions_pass_after_patch"] is True


@pytest.mark.parametrize("category", ["security", "regression"])
@pytest.mark.parametrize("bad_status", ["failed", "error"])
def test_any_post_patch_failure_or_error_rejects_patch(category, bad_status):
    after = _phase(**{category: ("passed", bad_status)})
    verdict = compute_verdict(_phase(reproduced=True), after)
    assert verdict["status"] == "FAILED"
    assert verdict["exploit_blocked_after_patch"] is (category != "security")
    assert verdict["regressions_pass_after_patch"] is (category != "regression")
    assert any(f"idor.{category}_1" in reason for reason in verdict["reasons"])


@pytest.mark.parametrize("category", ["security", "regression"])
def test_empty_post_patch_group_is_not_evidence_of_success(category):
    verdict = compute_verdict(_phase(reproduced=True), _phase(**{category: ()}))
    assert verdict["status"] == "FAILED"
    assert verdict["exploit_blocked_after_patch"] is (category != "security")
    assert verdict["regressions_pass_after_patch"] is (category != "regression")
    assert any(f"no {category} tests" in reason for reason in verdict["reasons"])


@pytest.mark.parametrize("broken_phase", ["before_patch", "after_patch"])
def test_load_error_in_either_phase_prevents_verification(broken_phase):
    phases = {"before_patch": _phase(reproduced=True), "after_patch": _phase()}
    phases[broken_phase]["load_error"] = "RuntimeError: fixture failed to start"
    verdict = compute_verdict(phases["before_patch"], phases["after_patch"])
    assert verdict["status"] == "FAILED"
    assert any(broken_phase in reason and "fixture failed to start" in reason
               for reason in verdict["reasons"])
    if broken_phase == "after_patch":
        assert verdict["exploit_blocked_after_patch"] is False
        assert verdict["regressions_pass_after_patch"] is False
