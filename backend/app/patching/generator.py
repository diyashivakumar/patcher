"""Deterministic patch generation for supported findings.

Strategies
  sqli  parameterized_query  rewrite the string-built SQL into constant SQL + bound parameters
  idor  ownership_check      call the module's existing access-check helper and abort(403) on failure
  idor  deny_all_demo        DEMO ONLY: deliberately over-restrictive patch that denies every request.
                             It exists so the Proof-of-Fix engine can be shown rejecting it.

A patch is a contiguous block of lines [line_start, line_end] in one file that is
replaced by new lines. Nothing is written to disk here; see applier.py.
"""
import ast
import difflib
from dataclasses import dataclass

from app.scanner.common import call_name, names_in
from app.scanner.engine import scan_source
from app.scanner.idor import CURRENT_USER, authz_helpers
from app.scanner.sqli import EXEC_METHODS

STRATEGIES = {
    "sqli": ["parameterized_query"],
    "idor": ["ownership_check", "deny_all_demo"],
}
DEFAULT_STRATEGY = {"sqli": "parameterized_query", "idor": "ownership_check"}


class PatchNotSupported(Exception):
    """The finding is real but this code shape is outside the automatic patcher's scope."""


@dataclass
class PatchProposal:
    strategy: str
    file_path: str
    line_start: int
    line_end: int
    original_snippet: str
    patched_snippet: str
    diff: str
    rationale: str
    validation: dict


def generate_patch(vuln_type, evidence, file_text, file_path, strategy=None):
    strategy = strategy or DEFAULT_STRATEGY.get(vuln_type)
    if strategy not in STRATEGIES.get(vuln_type, []):
        raise PatchNotSupported(f"Strategy '{strategy}' is not available for {vuln_type} findings")
    tree = ast.parse(file_text)
    lines = file_text.splitlines(keepends=True)
    if strategy == "parameterized_query":
        start, end, new_block, rationale = _sqli_parameterize(tree, lines, evidence)
    else:
        start, end, new_block, rationale = _idor_insert_check(tree, lines, evidence, deny_all=(strategy == "deny_all_demo"))

    new_lines = lines[:start - 1] + new_block + lines[end:]
    new_text = "".join(new_lines)
    diff = "".join(difflib.unified_diff(lines, new_lines, f"a/{file_path}", f"b/{file_path}"))
    return PatchProposal(
        strategy=strategy,
        file_path=file_path,
        line_start=start,
        line_end=end,
        original_snippet="".join(lines[start - 1:end]),
        patched_snippet="".join(new_block),
        diff=diff,
        rationale=rationale,
        validation=_validate(vuln_type, evidence, new_text, file_path),
    )


def _validate(vuln_type, evidence, new_text, file_path):
    """Static checks only. Real proof comes from the verification engine."""
    try:
        ast.parse(new_text)
    except SyntaxError as exc:
        return {"syntax_ok": False, "error": f"line {exc.lineno}: {exc.msg}", "target_finding_cleared": False}
    remaining = scan_source(new_text, file_path)
    still_there = [f for f in remaining
                   if f.vuln_type == vuln_type and f.evidence.get("function") == evidence.get("function")]
    return {
        "syntax_ok": True,
        "target_finding_cleared": not still_there,
        "remaining_findings_in_file": len(remaining),
        "note": "Static re-scan of the patched file. This is not verification; run the Proof-of-Fix engine.",
    }


# ---------------------------------------------------------------- SQL injection

def _byte_col_to_char(line, col):
    return len(line.encode("utf-8")[:col].decode("utf-8", errors="ignore"))


def _py_string(text):
    return '"' + text.encode("unicode_escape").decode("ascii").replace('"', '\\"') + '"'


def _sql_parts(expr):
    """Split an f-string / concatenation into [("lit", str) | ("expr", node)]."""
    if isinstance(expr, ast.Constant) and isinstance(expr.value, str):
        return [("lit", expr.value)]
    if isinstance(expr, ast.JoinedStr):
        parts = []
        for v in expr.values:
            if isinstance(v, ast.Constant):
                parts.append(("lit", v.value))
            elif v.conversion != -1 or v.format_spec is not None:
                raise PatchNotSupported("f-string conversions/format specs inside SQL are not auto-patched")
            else:
                parts.append(("expr", v.value))
        return parts
    if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Add):
        return _sql_parts(expr.left) + _sql_parts(expr.right)
    if isinstance(expr, (ast.BinOp, ast.Call)):
        raise PatchNotSupported("Only f-string and '+' concatenation SQL is auto-patched; "
                                "%-format and .format() need a manual fix (see remediation)")
    return [("expr", expr)]


def _param_source(prefix, node, suffix):
    src = ast.unparse(node)
    if not prefix and not suffix:
        return src
    if '"' in src or "\\" in src:
        return " + ".join(p for p in (_py_string(prefix) if prefix else "", f"str({src})",
                                      _py_string(suffix) if suffix else "") if p)
    esc = lambda s: s.replace("{", "{{").replace("}", "}}").replace('"', '\\"')  # noqa: E731
    return f'f"{esc(prefix)}{{{src}}}{esc(suffix)}"'


def build_parameterized(parts, placeholder):
    """Return (sql_text, [param source strings])."""
    sql, params = "", []
    parts = list(parts)
    i = 0
    while i < len(parts):
        kind, value = parts[i]
        if kind == "lit":
            sql += value
            i += 1
            continue
        if sql.count("'") % 2 == 1:  # inside a quoted SQL string literal
            quote = sql.rfind("'")
            prefix = sql[quote + 1:]
            nxt = parts[i + 1] if i + 1 < len(parts) else None
            if not nxt or nxt[0] != "lit" or "'" not in nxt[1]:
                raise PatchNotSupported("Several values inside one quoted SQL literal are not auto-patched")
            close = nxt[1].index("'")
            suffix = nxt[1][:close]
            sql = sql[:quote] + placeholder
            params.append(_param_source(prefix, value, suffix))
            parts[i + 1] = ("lit", nxt[1][close + 1:])
        else:
            sql += placeholder
            params.append(_param_source("", value, ""))
        i += 1
    if placeholder == "%s":
        # psycopg / pymysql treat a literal % as a format character when parameters are passed.
        sql = sql.replace("%", "%%").replace("%%s", "%s")
    return sql, params


def _placeholder_for(tree):
    for node in ast.walk(tree):
        mods = []
        if isinstance(node, ast.Import):
            mods = [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom) and node.module:
            mods = [node.module]
        if any(m.split(".")[0] in ("psycopg", "psycopg2", "pymysql", "MySQLdb", "mysql") for m in mods):
            return "%s"
    return "?"


def _sqli_parameterize(tree, lines, evidence):
    sink_line, query_line = evidence["sink_line"], evidence["query_line"]
    call = next((n for n in ast.walk(tree) if isinstance(n, ast.Call) and n.lineno == sink_line
                 and call_name(n) in EXEC_METHODS and n.args), None)
    if call is None:
        raise PatchNotSupported("Could not locate the execute() call; the file changed since the scan")
    if len(call.args) > 1 or call.keywords:
        raise PatchNotSupported("execute() already receives parameters; review this query manually")

    arg = call.args[0]
    assign = None
    if isinstance(arg, ast.Name):
        assign = next((n for n in ast.walk(tree) if isinstance(n, ast.Assign) and n.lineno == query_line
                       and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name)
                       and n.targets[0].id == arg.id), None)
        if assign is None:
            raise PatchNotSupported("Could not locate the SQL string assignment")
        if assign.end_lineno >= sink_line:
            raise PatchNotSupported("SQL assignment and execute() share a line")
        expr = assign.value
    else:
        expr = arg

    sql, params = build_parameterized(_sql_parts(expr), _placeholder_for(tree))
    params_src = "(" + ", ".join(params) + ("," if len(params) == 1 else "") + ")"

    start = min(query_line, sink_line)
    end = max(assign.end_lineno if assign else call.end_lineno, call.end_lineno)
    block = lines[start - 1:end]

    def edit(line_no, col, end_line_no, end_col, new_text):
        i, j = line_no - start, end_line_no - start
        a = block[i][:_byte_col_to_char(block[i], col)]
        b = block[j][_byte_col_to_char(block[j], end_col):]
        block[i:j + 1] = [a + new_text + b]

    # Edit bottom-up so earlier positions stay valid.
    if assign is not None:
        edit(arg.end_lineno, arg.end_col_offset, arg.end_lineno, arg.end_col_offset, f", {params_src}")
        edit(expr.lineno, expr.col_offset, expr.end_lineno, expr.end_col_offset, _py_string(sql))
    else:
        edit(arg.lineno, arg.col_offset, arg.end_lineno, arg.end_col_offset, f"{_py_string(sql)}, {params_src}")

    rationale = (
        f"The SQL text is now a constant ({_py_string(sql)}) and the {len(params)} user-influenced "
        f"value(s) are passed separately as bound parameters {params_src}. The database driver sends them "
        "as data, so quotes or SQL keywords in the input can no longer change the query. Wildcards that "
        "were part of the original string literal (e.g. % for LIKE) are moved into the parameter so search "
        "behaviour is unchanged."
    )
    return start, end, block, rationale


# ---------------------------------------------------------------- IDOR

def _module_defines(tree, name):
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and any((a.asname or a.name) == name for a in node.names):
            return True
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
            return True
    return False


def _idor_insert_check(tree, lines, evidence, deny_all):
    func = next((n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
                 and n.name == evidence["function"] and n.lineno == evidence["function_line"]), None)
    if func is None:
        raise PatchNotSupported("Could not locate the route function; the file changed since the scan")
    if not _module_defines(tree, "abort"):
        raise PatchNotSupported("flask.abort is not imported in this module")

    idx = next((i for i, s in enumerate(func.body) if s.lineno == evidence["lookup_line"]), None)
    if idx is None:
        raise PatchNotSupported("The record lookup is not a top-level statement of the route")
    anchor = func.body[idx]
    resource = evidence.get("resource_variable")
    # Insert after a following "if <resource> is None: abort(404)" style guard, if present.
    nxt = func.body[idx + 1] if idx + 1 < len(func.body) else None
    if isinstance(nxt, ast.If) and resource and resource in names_in(nxt.test):
        anchor = nxt

    lookup_text = lines[func.body[idx].lineno - 1]
    indent = lookup_text[: len(lookup_text) - len(lookup_text.lstrip())]
    inserted = []
    if deny_all:
        inserted.append(f'{indent}abort(403)  # DEMO ONLY: deliberately over-restrictive "fix" - denies everyone\n')
        rationale = (
            "DEMONSTRATION PATCH. This blocks the IDOR by refusing every request to this route, including "
            "the document's owner and authorised teachers. It is intentionally wrong: it closes the hole but "
            "breaks legitimate access. The Proof-of-Fix engine's PrivilegeMap regression tests should reject it."
        )
    else:
        if not resource:
            raise PatchNotSupported("The looked-up record is not assigned to a variable")
        helpers = authz_helpers(tree)
        if not helpers:
            raise PatchNotSupported("No access-check helper (e.g. can_view_document(user, doc)) exists in "
                                    "this module; write the authorisation rule manually")
        preferred = sorted(helpers, key=lambda h: 0 if any(w in h["name"] for w in ("view", "read", "access")) else 1)
        helper = preferred[0]["name"]
        user_var = evidence.get("current_user_variable")
        if not user_var:
            getter = next((n.name for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
                           and CURRENT_USER.search(n.name) and not n.args.args), None)
            if not getter:
                raise PatchNotSupported("No way to obtain the current user was found in this module")
            user_var = "current_user"
            inserted.append(f"{indent}{user_var} = {getter}()\n")
        inserted.append(f"{indent}if not {helper}({user_var}, {resource}):\n")
        inserted.append(f"{indent}    abort(403)\n")
        rationale = (
            f"After loading '{resource}' (and after the existing not-found check), the route now calls the "
            f"module's existing authorisation helper {helper}({user_var}, {resource}) and returns HTTP 403 when "
            "it fails. This reuses the authorisation rule already defined in the module instead of inventing a "
            "new one, so users the rule allows keep access while everyone else is denied. Whether that holds "
            "in practice is checked by the PrivilegeMap tests, not assumed."
        )

    start, end = func.lineno, anchor.end_lineno
    block = lines[start - 1:end] + inserted
    return start, end, block, rationale
