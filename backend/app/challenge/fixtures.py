"""Version-controlled candidate fix batches for SQLi and IDOR demonstration reliability.

Each candidate contains real source code representing common AI-generated or developer patterns:
  - Genuine defensive fix
  - Fake fix (changes string but remains vulnerable)
  - Naive blocklist (bypassed by gauntlet variants)
  - Over-restrictive (breaks legitimate users)
  - Data leak (leaks canary tokens in response)
  - Unsafe code (violates AST safety contract)
"""

SQLI_CACHED_CANDIDATES = [
    {
        "name": "Candidate #1: Parameterized Bound Query",
        "source_type": "cached",
        "model_name": "gemma4:e2b",
        "source_code": """def search():
    term = request.args.get("q", "")
    sql = "SELECT id, title FROM documents WHERE is_public = 1 AND title LIKE ?"
    rows = get_db().execute(sql, (f"%{term}%",)).fetchall()
    return jsonify([dict(r) for r in rows])""",
    },
    {
        "name": "Candidate #2: String Strip & Trim (Fake Fix)",
        "source_type": "cached",
        "model_name": "chatgpt-4o-pasted",
        "source_code": """def search():
    term = request.args.get("q", "").strip()
    sql = f"SELECT id, title FROM documents WHERE is_public = 1 AND title LIKE '%{term}%'"
    rows = get_db().execute(sql).fetchall()
    return jsonify([dict(r) for r in rows])""",
    },
    {
        "name": "Candidate #3: Naive '--' Comment Filter (Bypassed)",
        "source_type": "cached",
        "model_name": "copilot-auto",
        "source_code": """def search():
    term = request.args.get("q", "")
    if "--" in term or "' or" in term.lower():
        abort(400)
    sql = f"SELECT id, title FROM documents WHERE is_public = 1 AND title LIKE '%{term}%'"
    rows = get_db().execute(sql).fetchall()
    return jsonify([dict(r) for r in rows])""",
    },
    {
        "name": "Candidate #4: Deny All Queries (Over-Restrictive)",
        "source_type": "cached",
        "model_name": "claude-sonnet-suggested",
        "source_code": """def search():
    term = request.args.get("q", "")
    # Overly aggressive defense: rejects any search with special characters
    if any(c in term for c in ["'", '"', " ", "-", "=", ";", "%"]):
        abort(400)
    sql = "SELECT id, title FROM documents WHERE is_public = 1 AND title LIKE ?"
    rows = get_db().execute(sql, (f"%{term}%",)).fetchall()
    return jsonify([dict(r) for r in rows])""",
    },
    {
        "name": "Candidate #5: Debug Error Traceback (Data Leak)",
        "source_type": "cached",
        "model_name": "deepseek-coder",
        "source_code": """def search():
    term = request.args.get("q", "")
    try:
        sql = "SELECT id, title FROM documents WHERE is_public = 1 AND title LIKE ?"
        rows = get_db().execute(sql, (f"%{term}%",)).fetchall()
        return jsonify([dict(r) for r in rows])
    except Exception as exc:
        # Debug response leaks synthetic system tokens
        return jsonify({"error": str(exc), "canary_leak": "tok-alice-SYNTHETIC"}), 400""",
    },
    {
        "name": "Candidate #6: Subprocess Shell Script (Unsafe Code)",
        "source_type": "cached",
        "model_name": "unknown-ai",
        "source_code": """def search():
    import os
    os.system("echo search_executed")
    return jsonify([])""",
    },
    {
        "name": "Candidate #7: Named Parameter Tuple Query",
        "source_type": "cached",
        "model_name": "gemma4:e2b",
        "source_code": """def search():
    q = request.args.get("q", "")
    pattern = "%" + q + "%"
    sql = "SELECT id, title FROM documents WHERE is_public = 1 AND title LIKE ?"
    cursor = get_db().cursor()
    cursor.execute(sql, (pattern,))
    results = cursor.fetchall()
    return jsonify([dict(row) for row in results])""",
    },
    {
        "name": "Candidate #8: Quote Replacement Regex (Bypassed)",
        "source_type": "cached",
        "model_name": "chatgpt-3.5-legacy",
        "source_code": """def search():
    term = request.args.get("q", "").replace("'", "''")
    # Quote doubling still leaves UNION or numeric injection if not properly parameterized
    sql = f"SELECT id, title FROM documents WHERE is_public = 1 AND title LIKE '%{term}%'"
    rows = get_db().execute(sql).fetchall()
    return jsonify([dict(r) for r in rows])""",
    },
]

IDOR_CACHED_CANDIDATES = [
    {
        "name": "Candidate #1: Server-Side can_view_document Check",
        "source_type": "cached",
        "model_name": "gemma4:e2b",
        "source_code": """def get_document(doc_id):
    user = get_current_user()
    doc = query_one("SELECT id, owner_id, title, body, is_public FROM documents WHERE id = ?", (doc_id,))
    if doc is None:
        abort(404)
    if not can_view_document(user, doc):
        abort(403)
    return jsonify(dict(doc))""",
    },
    {
        "name": "Candidate #2: Unconditional Deny (Over-Restrictive)",
        "source_type": "cached",
        "model_name": "copilot-auto",
        "source_code": """def get_document(doc_id):
    user = get_current_user()
    doc = query_one("SELECT id, owner_id, title, body, is_public FROM documents WHERE id = ?", (doc_id,))
    if doc is None:
        abort(404)
    # Blocks legitimate users from viewing their own documents!
    abort(403)
    return jsonify(dict(doc))""",
    },
    {
        "name": "Candidate #3: Require Login Only (Fake Fix)",
        "source_type": "cached",
        "model_name": "chatgpt-4o-pasted",
        "source_code": """def get_document(doc_id):
    user = get_current_user()
    if user is None:
        abort(401)
    doc = query_one("SELECT id, owner_id, title, body, is_public FROM documents WHERE id = ?", (doc_id,))
    if doc is None:
        abort(404)
    # Checks authentication but completely ignores authorization/ownership!
    return jsonify(dict(doc))""",
    },
    {
        "name": "Candidate #4: Strict Owner Only (Bypassed Teacher Role)",
        "source_type": "cached",
        "model_name": "claude-sonnet-suggested",
        "source_code": """def get_document(doc_id):
    user = get_current_user()
    doc = query_one("SELECT id, owner_id, title, body, is_public FROM documents WHERE id = ?", (doc_id,))
    if doc is None:
        abort(404)
    if not doc["is_public"] and (user is None or doc["owner_id"] != user["id"]):
        abort(403)
    return jsonify(dict(doc))""",
    },
    {
        "name": "Candidate #5: Error Body Leaks Document (Data Leak)",
        "source_type": "cached",
        "model_name": "deepseek-coder",
        "source_code": """def get_document(doc_id):
    user = get_current_user()
    doc = query_one("SELECT id, owner_id, title, body, is_public FROM documents WHERE id = ?", (doc_id,))
    if doc is None:
        abort(404)
    if not can_view_document(user, doc):
        # Returns 403 status but leaks the document body in the JSON payload!
        return jsonify({"error": "Forbidden", "leaked": doc["body"]}), 403
    return jsonify(dict(doc))""",
    },
    {
        "name": "Candidate #6: File System Access (Unsafe Code)",
        "source_type": "cached",
        "model_name": "unknown-ai",
        "source_code": """def get_document(doc_id):
    open("/tmp/pwned.txt", "w").write(str(doc_id))
    return jsonify({})""",
    },
]


def get_cached_candidates(vuln_type: str) -> list[dict]:
    """Retrieve pre-built candidate batch for the specified vulnerability type."""
    if vuln_type == "sqli":
        return list(SQLI_CACHED_CANDIDATES)
    return list(IDOR_CACHED_CANDIDATES)
