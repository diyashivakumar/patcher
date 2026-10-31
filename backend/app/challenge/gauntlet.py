"""Exploit Variant Gauntlet for PatchProof.

Subjecting candidate security patches to:
  1. The original exploit payload.
  2. Diverse exploit variations (comment syntax, encoded payloads, quote-balancing, UNION queries).
  3. Legitimate application regression tests.
"""
from app.challenge.schemas import GauntletTestEvidence
from testing.harness import call, json_or_none


def _get_titles(resp):
    data = json_or_none(resp)
    if not isinstance(data, list):
        return None
    return {str(r.get("title")) for r in data if isinstance(r, dict)}


def run_sqli_gauntlet(client) -> tuple[list[GauntletTestEvidence], list[str]]:
    """Run SQL injection gauntlet against client. Returns (results, raw_response_bodies)."""
    results: list[GauntletTestEvidence] = []
    response_bodies: list[str] = []

    # 1. Original Demonstration Exploit
    orig_payload = "' OR 1=1 --"
    resp, ev = call(client, "GET", "/search", params={"q": orig_payload})
    body = resp.get_data(as_text=True)
    response_bodies.append(body)
    titles = _get_titles(resp) or set()
    leaked = bool(titles & {"Alice Private Diary", "Bob Private Grades"})
    passed = not leaked and resp.status_code in (200, 400)
    results.append(GauntletTestEvidence(
        payload_id="sqli.original_tautology",
        name="Original Exploit: Tautology ( ' OR 1=1 -- )",
        payload=orig_payload,
        category="original_exploit",
        expected="Private documents blocked; HTTP 200/400 with no private records",
        actual=f"HTTP {resp.status_code}, leaked={leaked}",
        passed=passed,
        exploit_succeeded=leaked,
        response_status=resp.status_code,
        evidence_snippet=body[:200],
    ))

    # 2. Gauntlet Variants
    variants = [
        (
            "sqli.variant_union_users",
            "Gauntlet: UNION User Token Extraction",
            "' UNION SELECT id, api_token FROM users --",
            lambda r, b: "SYNTHETIC" in b,
            "No user tokens in results",
        ),
        (
            "sqli.variant_comment_c_style",
            "Gauntlet: C-Style Comment ( /* )",
            "' OR 1=1 /*",
            lambda r, b: bool((_get_titles(r) or set()) & {"Alice Private Diary", "Bob Private Grades"}),
            "C-style comment blocked; no private docs",
        ),
        (
            "sqli.variant_comment_hash",
            "Gauntlet: Hash Comment ( # )",
            "' OR 1=1 #",
            lambda r, b: bool((_get_titles(r) or set()) & {"Alice Private Diary", "Bob Private Grades"}),
            "Hash comment blocked; no private docs",
        ),
        (
            "sqli.variant_boolean_tautology",
            "Gauntlet: String Comparison Tautology",
            "' OR 'x'='x",
            lambda r, b: bool((_get_titles(r) or set()) & {"Alice Private Diary", "Bob Private Grades"}),
            "String tautology treated as text",
        ),
        (
            "sqli.variant_quote_balance",
            "Gauntlet: Balanced Parenthesis Injection",
            "') OR ('1'='1",
            lambda r, b: bool((_get_titles(r) or set()) & {"Alice Private Diary", "Bob Private Grades"}),
            "Parenthesis injection blocked",
        ),
    ]

    for test_id, name, payload, check_exploit, exp in variants:
        v_resp, v_ev = call(client, "GET", "/search", params={"q": payload})
        v_body = v_resp.get_data(as_text=True)
        response_bodies.append(v_body)
        exp_succeeded = check_exploit(v_resp, v_body)
        v_passed = not exp_succeeded and v_resp.status_code in (200, 400)
        results.append(GauntletTestEvidence(
            payload_id=test_id,
            name=name,
            payload=payload,
            category="variant_gauntlet",
            expected=exp,
            actual=f"HTTP {v_resp.status_code}, exploit_succeeded={exp_succeeded}",
            passed=v_passed,
            exploit_succeeded=exp_succeeded,
            response_status=v_resp.status_code,
            evidence_snippet=v_body[:200],
        ))

    # 3. Legitimate Regression Tests
    regressions = [
        ("sqli.reg_algebra", "Search Public 'Algebra'", "Algebra", lambda t, s: s == 200 and "Algebra Notes" in (t or set())),
        ("sqli.reg_empty", "Empty Search Lists Public", "", lambda t, s: s == 200 and len(t or set()) >= 3),
        ("sqli.reg_apostrophe", "Search with Apostrophe (O'Brien)", "O'Brien", lambda t, s: s == 200 and "O'Brien Reading List" in (t or set())),
    ]

    for test_id, name, query, check_pass in regressions:
        r_resp, r_ev = call(client, "GET", "/search", params={"q": query})
        r_body = r_resp.get_data(as_text=True)
        r_titles = _get_titles(r_resp)
        r_passed = check_pass(r_titles, r_resp.status_code)
        results.append(GauntletTestEvidence(
            payload_id=test_id,
            name=name,
            payload=query,
            category="regression",
            expected="HTTP 200 with public documents matching query",
            actual=f"HTTP {r_resp.status_code}, titles={sorted(r_titles) if r_titles else None}",
            passed=r_passed,
            exploit_succeeded=None,
            response_status=r_resp.status_code,
            evidence_snippet=r_body[:200],
        ))

    return results, response_bodies


def run_idor_gauntlet(client) -> tuple[list[GauntletTestEvidence], list[str]]:
    """Run IDOR gauntlet against client. Returns (results, raw_response_bodies)."""
    results: list[GauntletTestEvidence] = []
    response_bodies: list[str] = []

    # 1. Original Exploit: Alice reads Bob's Document (id=2)
    resp, ev = call(client, "GET", "/documents/2", actor="alice")
    body = resp.get_data(as_text=True)
    response_bodies.append(body)
    data = json_or_none(resp)
    exploited = resp.status_code == 200 and isinstance(data, dict) and data.get("id") == 2
    passed = resp.status_code in (401, 403, 404) and not exploited
    results.append(GauntletTestEvidence(
        payload_id="idor.original_cross_student",
        name="Original Exploit: Alice reads Bob's Private Document",
        payload="GET /documents/2 (as alice)",
        category="original_exploit",
        expected="Access denied (HTTP 403/401/404); no private document returned",
        actual=f"HTTP {resp.status_code}, exploit_succeeded={exploited}",
        passed=passed,
        exploit_succeeded=exploited,
        response_status=resp.status_code,
        evidence_snippet=body[:200],
    ))

    # 2. Gauntlet Variants
    variants = [
        ("idor.variant_bob_reads_alice", "Gauntlet: Bob reads Alice's Doc (id=1)", "/documents/1", "bob", 1),
        ("idor.variant_unassigned_teacher", "Gauntlet: Mr. Okafor reads Bob's Doc (id=2)", "/documents/2", "mr_okafor", 2),
        ("idor.variant_anonymous_private", "Gauntlet: Anonymous reads Private Doc (id=1)", "/documents/1", "anonymous", 1),
    ]

    for test_id, name, path, actor, target_id in variants:
        v_resp, v_ev = call(client, "GET", path, actor=actor)
        v_body = v_resp.get_data(as_text=True)
        response_bodies.append(v_body)
        v_data = json_or_none(v_resp)
        v_exploited = v_resp.status_code == 200 and isinstance(v_data, dict) and v_data.get("id") == target_id
        v_passed = v_resp.status_code in (401, 403, 404) and not v_exploited
        results.append(GauntletTestEvidence(
            payload_id=test_id,
            name=name,
            payload=f"GET {path} (as {actor})",
            category="variant_gauntlet",
            expected=f"Access denied for unauthorized actor {actor}",
            actual=f"HTTP {v_resp.status_code}, exploit_succeeded={v_exploited}",
            passed=v_passed,
            exploit_succeeded=v_exploited,
            response_status=v_resp.status_code,
            evidence_snippet=v_body[:200],
        ))

    # 3. Legitimate Regression Tests
    regressions = [
        ("idor.reg_alice_own", "Regression: Alice reads Own Document (id=1)", "/documents/1", "alice", 1),
        ("idor.reg_teacher_assigned", "Regression: Ms. Rivera reads Assigned Student Doc (id=1)", "/documents/1", "ms_rivera", 1),
        ("idor.reg_anonymous_public", "Regression: Anonymous reads Public Doc (id=3)", "/documents/3", "anonymous", 3),
        ("idor.reg_mine_endpoint", "Regression: Alice lists Own Documents (/documents/mine)", "/documents/mine", "alice", None),
    ]

    for test_id, name, path, actor, target_id in regressions:
        r_resp, r_ev = call(client, "GET", path, actor=actor)
        r_body = r_resp.get_data(as_text=True)
        r_data = json_or_none(r_resp)
        if target_id is not None:
            r_passed = r_resp.status_code == 200 and isinstance(r_data, dict) and r_data.get("id") == target_id
        else:
            r_passed = r_resp.status_code == 200 and isinstance(r_data, list) and len(r_data) >= 1
        results.append(GauntletTestEvidence(
            payload_id=test_id,
            name=name,
            payload=f"GET {path} (as {actor})",
            category="regression",
            expected="Legitimate access allowed (HTTP 200)",
            actual=f"HTTP {r_resp.status_code}",
            passed=r_passed,
            exploit_succeeded=None,
            response_status=r_resp.status_code,
            evidence_snippet=r_body[:200],
        ))

    return results, response_bodies

