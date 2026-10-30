from pathlib import Path

import pytest

from app.config import REPO_ROOT
from app.patching.generator import PatchNotSupported, build_parameterized, generate_patch
from app.scanner.engine import scan_directory, scan_source

FIXTURES = REPO_ROOT / "fixtures"
VULN_APP = (FIXTURES / "vulnerable_app" / "app.py").read_text(encoding="utf-8")


def _line_of(text, needle):
    return next(i for i, line in enumerate(text.splitlines(), 1) if needle in line)


def test_scanner_finds_exactly_the_two_planted_flaws():
    findings, files, warnings = scan_directory(FIXTURES / "vulnerable_app")
    assert files == 1 and warnings == []
    by_type = {f.vuln_type: f for f in findings}
    assert sorted(by_type) == ["idor", "sqli"]
    assert len(findings) == 2

    sqli = by_type["sqli"]
    assert sqli.line_start == _line_of(VULN_APP, 'sql = f"SELECT')
    assert sqli.line_end == _line_of(VULN_APP, "execute(sql)")
    assert sqli.severity == "CRITICAL" and sqli.evidence["user_controlled"] is True
    assert sqli.evidence["interpolated_inputs"][0]["name"] == "term"

    idor = by_type["idor"]
    assert idor.evidence["function"] == "get_document"
    assert idor.line_start == _line_of(VULN_APP, '@app.route("/documents/<int:doc_id>")')
    assert idor.evidence["available_authz_helpers"][0]["name"] == "can_view_document"


@pytest.mark.parametrize("variant", ["patched_reference", "over_restrictive"])
def test_scanner_reports_nothing_on_patched_variants(variant):
    findings, _, _ = scan_directory(FIXTURES / "variants" / variant)
    assert findings == []


@pytest.mark.parametrize("code", [
    'cur.execute("SELECT * FROM t WHERE id = ?", (uid,))',
    'cur.execute("SELECT 1")',
    'q = "SELECT * FROM t"\ncur.execute(q)',
    'msg = f"hello {name}"\nlog.execute(msg)',  # no SQL keywords -> not SQL
])
def test_sqli_safe_patterns_not_flagged(code):
    assert [f for f in scan_source(code, "x.py") if f.vuln_type == "sqli"] == []


@pytest.mark.parametrize("code", [
    'cur.execute("SELECT * FROM t WHERE id = " + uid)',
    'cur.execute("SELECT * FROM t WHERE id = %s" % uid)',
    'cur.execute("SELECT * FROM t WHERE id = {}".format(uid))',
    'q = "SELECT * FROM t WHERE a = 1"\nq += " AND b = " + val\ncur.execute(q)',
])
def test_sqli_other_constructions_flagged(code):
    assert [f.vuln_type for f in scan_source(code, "x.py")] == ["sqli"]


def test_idor_ownership_filtered_query_not_flagged():
    code = '''
@app.route("/notes/<int:note_id>")
def note(note_id):
    row = db.execute("SELECT * FROM notes WHERE id = ? AND owner_id = ?", (note_id, uid)).fetchone()
    return row
'''
    assert scan_source(code, "x.py") == []


def test_sqli_patch_matches_reference_and_clears_finding():
    finding = next(f for f in scan_source(VULN_APP, "app.py") if f.vuln_type == "sqli")
    patch = generate_patch("sqli", finding.evidence, VULN_APP, "app.py")
    assert 'sql = "SELECT id, title FROM documents WHERE is_public = 1 AND title LIKE ?"' in patch.patched_snippet
    assert 'execute(sql, (f"%{term}%",))' in patch.patched_snippet
    assert patch.validation == {**patch.validation, "syntax_ok": True, "target_finding_cleared": True}
    reference = (FIXTURES / "variants" / "patched_reference" / "app.py").read_text(encoding="utf-8")
    assert patch.patched_snippet in reference


def test_idor_patch_uses_existing_helper():
    finding = next(f for f in scan_source(VULN_APP, "app.py") if f.vuln_type == "idor")
    patch = generate_patch("idor", finding.evidence, VULN_APP, "app.py")
    assert "if not can_view_document(user, doc):\n            abort(403)\n" in patch.patched_snippet
    assert patch.validation["target_finding_cleared"] is True


def test_deny_all_demo_patch_fools_static_rescan():
    finding = next(f for f in scan_source(VULN_APP, "app.py") if f.vuln_type == "idor")
    patch = generate_patch("idor", finding.evidence, VULN_APP, "app.py", "deny_all_demo")
    assert "abort(403)  # DEMO ONLY" in patch.patched_snippet
    # Static analysis alone would call this fixed -- only the Proof-of-Fix run exposes it.
    assert patch.validation["target_finding_cleared"] is True


def test_build_parameterized_numeric_and_quoted():
    import ast
    parts = [("lit", "SELECT * FROM t WHERE id = "), ("expr", ast.parse("uid", mode="eval").body),
             ("lit", " AND name = '"), ("expr", ast.parse("n", mode="eval").body), ("lit", "'")]
    sql, params = build_parameterized(parts, "?")
    assert sql == "SELECT * FROM t WHERE id = ? AND name = ?" and params == ["uid", "n"]
    sql, _ = build_parameterized(parts, "%s")
    assert sql == "SELECT * FROM t WHERE id = %s AND name = %s"


def test_percent_format_is_reported_but_not_auto_patched():
    code = 'def f(cur, uid):\n    cur.execute("SELECT * FROM t WHERE id = %s" % uid)\n'
    finding = scan_source(code, "x.py")[0]
    with pytest.raises(PatchNotSupported):
        generate_patch("sqli", finding.evidence, code, "x.py")


def test_unknown_strategy_rejected():
    finding = next(f for f in scan_source(VULN_APP, "app.py") if f.vuln_type == "sqli")
    with pytest.raises(PatchNotSupported):
        generate_patch("sqli", finding.evidence, VULN_APP, "app.py", "deny_all_demo")


def test_crlf_files_keep_line_endings(tmp_path):
    crlf = VULN_APP.replace("\n", "\r\n")
    finding = next(f for f in scan_source(crlf, "app.py") if f.vuln_type == "sqli")
    patch = generate_patch("sqli", finding.evidence, crlf, "app.py")
    assert patch.patched_snippet.endswith("\r\n") and "\n" not in patch.patched_snippet.replace("\r\n", "")
    assert Path  # keep import used
