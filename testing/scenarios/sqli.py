"""SQL injection scenario for GET /search.

Security tests send harmless, read-only injection payloads against the local
fixture. They PASS when the payload is treated as plain text (no data leaks).
Regression tests check that ordinary searches still behave correctly.
"""
from testing.harness import call, json_or_none
from testing.scenarios import REGRESSION, SECURITY, TestCase

PRIVATE_TITLES = {"Alice Private Diary", "Bob Private Grades"}
PUBLIC_TITLES = {"Algebra Notes", "Chemistry Lab Safety", "O'Brien Reading List"}


def _titles(response):
    data = json_or_none(response)
    if not isinstance(data, list):
        return None
    return {str(row.get("title")) for row in data if isinstance(row, dict)}


def _tautology(client):
    payload = "' OR 1=1 --"
    resp, evidence = call(client, "GET", "/search", params={"q": payload})
    titles = _titles(resp) or set()
    leaked = sorted(titles & PRIVATE_TITLES)
    exploited = bool(leaked)
    passed = not exploited and resp.status_code in (200, 400)
    if exploited:
        actual = f"Injection succeeded: private documents leaked {leaked}"
    elif resp.status_code >= 500:
        actual = f"Server error {resp.status_code} (payload reached the SQL parser)"
    else:
        actual = f"Payload treated as text; HTTP {resp.status_code}, no private documents returned"
    return {"passed": passed, "exploit_succeeded": exploited, "actual": actual, "evidence": evidence}


def _union(client):
    payload = "' UNION SELECT id, api_token FROM users --"
    resp, evidence = call(client, "GET", "/search", params={"q": payload})
    body = resp.get_data(as_text=True)
    exploited = "SYNTHETIC" in body
    passed = not exploited and resp.status_code in (200, 400)
    if exploited:
        actual = "Injection succeeded: synthetic user API tokens appeared in search results"
    elif resp.status_code >= 500:
        actual = f"Server error {resp.status_code} (payload reached the SQL parser)"
    else:
        actual = f"Payload treated as text; HTTP {resp.status_code}, no user data returned"
    return {"passed": passed, "exploit_succeeded": exploited, "actual": actual, "evidence": evidence}


def _expect_titles(client, query, must_include, must_equal=None):
    resp, evidence = call(client, "GET", "/search", params={"q": query})
    titles = _titles(resp)
    if resp.status_code != 200 or titles is None:
        return {"passed": False, "actual": f"HTTP {resp.status_code}, no result list", "evidence": evidence}
    ok = must_include <= titles and not (titles & PRIVATE_TITLES)
    if must_equal is not None:
        ok = ok and titles == must_equal
    return {"passed": ok, "actual": f"HTTP 200, titles={sorted(titles)}", "evidence": evidence}


TESTS = [
    TestCase(
        "sqli.tautology_leaks_private_docs", "sqli", SECURITY,
        "Tautology injection ( ' OR 1=1 -- )",
        "Tries to turn the WHERE clause into 'always true' so private documents are returned.",
        "No private documents returned; HTTP 200 or 400",
        _tautology,
    ),
    TestCase(
        "sqli.union_leaks_user_tokens", "sqli", SECURITY,
        "UNION injection reading the users table",
        "Tries to append a UNION SELECT that returns synthetic user API tokens.",
        "No user tokens returned; HTTP 200 or 400",
        _union,
    ),
    TestCase(
        "sqli.search_finds_public_doc", "sqli", REGRESSION,
        "Normal search finds a public document",
        "Searching 'Algebra' must return the public 'Algebra Notes' document.",
        "HTTP 200 and results include 'Algebra Notes'",
        lambda c: _expect_titles(c, "Algebra", {"Algebra Notes"}),
    ),
    TestCase(
        "sqli.empty_search_lists_public_docs", "sqli", REGRESSION,
        "Empty search lists every public document",
        "An empty query must list exactly the public documents and nothing private.",
        f"HTTP 200 and titles == {sorted(PUBLIC_TITLES)}",
        lambda c: _expect_titles(c, "", PUBLIC_TITLES, must_equal=PUBLIC_TITLES),
    ),
    TestCase(
        "sqli.search_with_apostrophe", "sqli", REGRESSION,
        "Search containing an apostrophe works",
        "Legitimate input with a quote (O'Brien) must be searchable, not crash the query.",
        "HTTP 200 and results include \"O'Brien Reading List\"",
        lambda c: _expect_titles(c, "O'Brien", {"O'Brien Reading List"}),
    ),
]
