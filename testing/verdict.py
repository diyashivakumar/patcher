"""Proof-of-Fix verdict rules. Deterministic: computed only from executed test results.

VERIFIED            original exploit reproduced before the patch, AND every
                    security test passes after the patch, AND every regression
                    test passes after the patch.
PARTIALLY_VERIFIED  every post-patch test passes, but the original exploit
                    could NOT be reproduced, so we cannot prove the patch is
                    what closed it.
FAILED              any post-patch security or regression test fails or errors,
                    a phase could not load/run, or a required test set is empty.

Missing tests are never counted as passed.
"""
VERIFIED = "VERIFIED"
PARTIALLY_VERIFIED = "PARTIALLY_VERIFIED"
FAILED = "FAILED"


def compute_verdict(before, after):
    reasons = []
    for label, phase in (("before_patch", before), ("after_patch", after)):
        if phase.get("load_error"):
            reasons.append(f"{label}: application could not be loaded: {phase['load_error']}")
    if reasons:
        return _verdict(FAILED, reasons, before, after)

    sec, reg = after["security_tests"], after["regression_tests"]
    if sec["total"] == 0:
        reasons.append("after_patch: no security tests were executed")
    if reg["total"] == 0:
        reasons.append("after_patch: no regression tests were executed")
    if sec["failed"] or sec["errors"]:
        names = [r["test_id"] for r in sec["results"] if r["status"] != "passed"]
        reasons.append(f"after_patch: security tests still failing (exploit not blocked): {names}")
    if reg["failed"] or reg["errors"]:
        names = [r["test_id"] for r in reg["results"] if r["status"] != "passed"]
        reasons.append(f"after_patch: regression tests failing (legitimate behaviour broken): {names}")
    if reasons:
        return _verdict(FAILED, reasons, before, after)

    if not before["exploit_reproduced"]:
        reasons.append("before_patch: original vulnerability was not reproduced, so the fix cannot be proven")
        return _verdict(PARTIALLY_VERIFIED, reasons, before, after)

    reasons.append("Original exploit reproduced before the patch")
    reasons.append(f"All {sec['total']} security tests pass after the patch")
    reasons.append(f"All {reg['total']} regression tests pass after the patch")
    return _verdict(VERIFIED, reasons, before, after)


def _verdict(status, reasons, before, after):
    return {
        "status": status,
        "reasons": reasons,
        "original_vulnerability_reproduced": bool(before.get("exploit_reproduced")),
        "exploit_blocked_after_patch": (
            not after.get("load_error")
            and after["security_tests"]["total"] > 0
            and after["security_tests"]["failed"] == 0
            and after["security_tests"]["errors"] == 0
        ),
        "regressions_pass_after_patch": (
            not after.get("load_error")
            and after["regression_tests"]["total"] > 0
            and after["regression_tests"]["failed"] == 0
            and after["regression_tests"]["errors"] == 0
        ),
    }
