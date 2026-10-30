"""IDOR / broken access control scenario for GET /documents/<id>.

Tests are generated from the PrivilegeMap: DENY rules become security tests,
ALLOW rules become regression tests.
"""
from testing.harness import call, json_or_none
from testing.privilege_map import ALLOW, DENY, PRIVILEGE_MAP, observed_decision
from testing.scenarios import REGRESSION, SECURITY, TestCase


def _make_runner(rule):
    def run(client):
        path = f"/documents/{rule.document_id}"
        resp, evidence = call(client, "GET", path, actor=rule.actor)
        observed = observed_decision(resp.status_code)
        if observed == ALLOW:
            data = json_or_none(resp)
            # A 200 must actually contain the requested document to count as ALLOW.
            if not (isinstance(data, dict) and data.get("id") == rule.document_id):
                observed = None
        passed = observed == rule.expected
        result = {
            "passed": passed,
            "actual": f"{observed or 'UNEXPECTED'} (HTTP {resp.status_code})",
            "evidence": evidence,
            "privilege_map": {
                "rule_id": rule.rule_id,
                "actor": rule.actor,
                "resource": f"document:{rule.document_id}",
                "expected": rule.expected,
                "observed": observed or "UNEXPECTED",
                "reason": rule.reason,
            },
        }
        if rule.expected == DENY:
            result["exploit_succeeded"] = observed == ALLOW
        return result

    return run


def _own_document_list(client):
    resp, evidence = call(client, "GET", "/documents/mine", actor="alice")
    data = json_or_none(resp)
    ids = sorted(row.get("id") for row in data) if isinstance(data, list) else None
    passed = resp.status_code == 200 and ids == [1]
    return {"passed": passed, "actual": f"HTTP {resp.status_code}, ids={ids}", "evidence": evidence}


TESTS = [
    TestCase(
        f"idor.{rule.rule_id}", "idor",
        SECURITY if rule.expected == DENY else REGRESSION,
        f"{rule.actor} -> document {rule.document_id}: expect {rule.expected}",
        rule.reason,
        rule.expected,
        _make_runner(rule),
    )
    for rule in PRIVILEGE_MAP
] + [
    TestCase(
        "idor.owner_lists_own_documents", "idor", REGRESSION,
        "alice lists her own documents",
        "GET /documents/mine must still return exactly alice's documents.",
        "HTTP 200 and ids == [1]",
        _own_document_list,
    ),
]
