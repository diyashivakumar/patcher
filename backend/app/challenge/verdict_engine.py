"""Authoritative Fix Court Verdict System.

Every candidate fix receives exactly one final verdict based strictly on executed test evidence,
forensics scanning, and gauntlet variants.

Verdict Priority:
  1. Safety validation failure                -> REJECTED_UNSAFE_CODE
  2. Actual protected canary exposure         -> DATA_LEAK
  3. Original demonstration exploit succeeds  -> FAKE_FIX
  4. Any Gauntlet variant succeeds            -> BYPASSED
  5. Legitimate user regression fails         -> OVER_RESTRICTIVE
  6. All required checks pass cleanly         -> GENUINE
  7. Inconclusive if execution errored        -> INCONCLUSIVE
"""
from app.challenge.schemas import ForensicsEvidence, GauntletTestEvidence, SafetyValidationResult, VerdictType


def determine_fix_court_verdict(
    safety: SafetyValidationResult,
    gauntlet_results: list[GauntletTestEvidence],
    forensics: ForensicsEvidence,
    execution_error: str | None = None,
) -> tuple[VerdictType, str, str | None]:
    """Compute authoritative Fix Court verdict.
    
    Returns (verdict, rationale, convicting_test_id).
    """
    # 1. Safety validation failure
    if not safety.valid:
        return (
            "REJECTED_UNSAFE_CODE",
            f"Code rejected by AST Safety Gate before execution: {safety.rejection_reason}",
            None,
        )

    # If the app crashed during import/execution
    if execution_error:
        return (
            "INCONCLUSIVE",
            f"Candidate could not be evaluated due to execution error: {execution_error}",
            None,
        )

    if not gauntlet_results:
        return ("INCONCLUSIVE", "No gauntlet test results were collected.", None)

    # 2. Data Exposure Forensics check
    if forensics.canary_detected:
        markers = ", ".join(forensics.detected_markers)
        return (
            "DATA_LEAK",
            f"Data Exposure Forensics detected protected synthetic canary markers in response payload: {markers}",
            "forensics.canary_detected",
        )

    # Separate test categories
    orig_tests = [t for t in gauntlet_results if t.category == "original_exploit"]
    variant_tests = [t for t in gauntlet_results if t.category == "variant_gauntlet"]
    regression_tests = [t for t in gauntlet_results if t.category == "regression"]

    # 3. Original demonstration exploit check -> FAKE FIX
    for t in orig_tests:
        if not t.passed or t.exploit_succeeded:
            return (
                "FAKE_FIX",
                f"Patch appeared to modify code, but original exploit still succeeded on '{t.name}'.",
                t.payload_id,
            )

    # 4. Gauntlet attack variant check -> BYPASSED
    for t in variant_tests:
        if not t.passed or t.exploit_succeeded:
            return (
                "BYPASSED",
                f"Original payload was blocked, but attack variant '{t.name}' successfully bypassed the patch.",
                t.payload_id,
            )

    # 5. Legitimate regression check -> OVER-RESTRICTIVE
    for t in regression_tests:
        if not t.passed:
            return (
                "OVER_RESTRICTIVE",
                f"Security tests passed, but legitimate application functionality broke on '{t.name}'.",
                t.payload_id,
            )

    # 6. All checks passed cleanly -> GENUINE
    return (
        "GENUINE",
        f"Verified fix: Original exploit blocked, all {len(variant_tests)} Gauntlet variants blocked, zero canaries leaked, and all {len(regression_tests)} regression tests passed.",
        None,
    )
