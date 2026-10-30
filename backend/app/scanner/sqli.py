"""SQL injection detector (CWE-89).

Supported pattern: a DB-API style `<obj>.execute(...)` / `executemany` / `executescript`
call whose SQL argument is built with string formatting instead of bound parameters:

  * f-strings                     f"... WHERE name = '{name}'"
  * concatenation                 "... WHERE id = " + user_id
  * percent formatting            "... WHERE id = %s" % user_id
  * str.format                    "... WHERE id = {}".format(user_id)

The SQL may be passed inline or through a local variable assigned in the same
function. A literal part of the string must look like SQL (SELECT, WHERE, ...).
Interpolated variables are traced one step back to see whether they come from
the HTTP request (request.args / form / json / view args or a URL path parameter).
"""
import ast
import re

from app.scanner.common import FindingData, call_name, iter_scopes, line_text, names_in, route_info, \
    scope_nodes, snippet

EXEC_METHODS = {"execute", "executemany", "executescript"}
SQL_WORDS = re.compile(r"\b(SELECT|INSERT|UPDATE|DELETE|WHERE|FROM|VALUES)\b", re.IGNORECASE)


def _literal_text(node):
    return " ".join(
        n.value for n in ast.walk(node) if isinstance(n, ast.Constant) and isinstance(n.value, str)
    )


def _flatten_add(node):
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _flatten_add(node.left) + _flatten_add(node.right)
    return [node]


def classify_sql_expr(node):
    """Return the unsafe construction kind for an expression, or None if it is safe/unknown."""
    if isinstance(node, ast.JoinedStr) and any(isinstance(v, ast.FormattedValue) for v in node.values):
        return "f-string"
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        parts = _flatten_add(node)
        has_str = any(isinstance(p, ast.JoinedStr) or (isinstance(p, ast.Constant) and isinstance(p.value, str))
                      for p in parts)
        has_dynamic = any(not isinstance(p, ast.Constant) for p in parts)
        if has_str and has_dynamic:
            return "concatenation"
    if (isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod)
            and isinstance(node.left, ast.Constant) and isinstance(node.left.value, str)):
        return "percent-format"
    if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format"
            and isinstance(node.func.value, ast.Constant) and isinstance(node.func.value.value, str)):
        return "str.format"
    return None


def _assignments(scope):
    """name -> list of (lineno, value_node, is_augmented) for simple local assignments."""
    found = {}
    for node in scope_nodes(scope):
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            found.setdefault(node.targets[0].id, []).append((node.lineno, node, False))
        elif isinstance(node, ast.AugAssign) and isinstance(node.target, ast.Name):
            found.setdefault(node.target.id, []).append((node.lineno, node, True))
    return found


def _resolve_sql(arg, assigns, before_line):
    """Return (kind, expr_node, assignment_node_or_None) for the SQL argument."""
    kind = classify_sql_expr(arg)
    if kind:
        return kind, arg, None
    if isinstance(arg, ast.Name):
        history = sorted((a for a in assigns.get(arg.id, []) if a[0] < before_line), key=lambda a: a[0])
        for _, node, augmented in reversed(history):
            if augmented:
                if isinstance(node.op, ast.Add) and not isinstance(node.value, ast.Constant):
                    return "concatenation", node.value, node
                continue
            kind = classify_sql_expr(node.value)
            return (kind, node.value, node) if kind else (None, None, None)
    return None, None, None


def _trace_inputs(expr, assigns, path_params, before_line, lines):
    """Describe where each interpolated variable comes from."""
    traced = []
    for name in sorted(names_in(expr)):
        if name in path_params:
            traced.append({"name": name, "source": "URL path parameter", "line": None, "user_controlled": True})
            continue
        history = [a for a in assigns.get(name, []) if a[0] < before_line]
        if not history:
            continue
        lineno, node, _ = max(history, key=lambda a: a[0])
        user = "request" in names_in(node.value)
        traced.append({"name": name, "source": line_text(lines, lineno).strip(), "line": lineno,
                       "user_controlled": user})
    return traced


def detect(tree, lines, rel_path):
    findings = []
    for scope in iter_scopes(tree):
        assigns = _assignments(scope)
        route = route_info(scope) if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)) else None
        path_params = set(route[2]) if route else set()
        for node in scope_nodes(scope):
            if not (isinstance(node, ast.Call) and call_name(node) in EXEC_METHODS and node.args):
                continue
            kind, expr, assign_node = _resolve_sql(node.args[0], assigns, node.lineno)
            if not kind:
                continue
            sql_text = _literal_text(expr)
            if isinstance(node.args[0], ast.Name):  # include text from earlier `q = "SELECT..."` / `q += ...`
                sql_text += " ".join(_literal_text(a[1]) for a in assigns.get(node.args[0].id, [])
                                     if a[0] < node.lineno)
            if not SQL_WORDS.search(sql_text):
                continue
            inputs = _trace_inputs(expr, assigns, path_params, node.lineno, lines)
            user_controlled = any(i["user_controlled"] for i in inputs)
            query_line = assign_node.lineno if assign_node else node.lineno
            start, end = min(query_line, node.lineno), max(query_line, node.lineno)
            text, first = snippet(lines, start, end)
            where = f"route {route[1]}" if route else f"function {getattr(scope, 'name', '<module>')}"
            findings.append(FindingData(
                vuln_type="sqli",
                title="SQL injection via string-built query",
                severity="CRITICAL" if user_controlled else "HIGH",
                severity_rationale=(
                    "HTTP request input flows directly into the SQL text with no authentication "
                    "required, so an attacker can read (or alter) any data the database user can access."
                    if user_controlled else
                    "The SQL text is built from variables with string formatting. No direct HTTP input "
                    "was traced, so exploitability depends on where those values originate."
                ),
                confidence="HIGH" if user_controlled else "MEDIUM",
                cwe="CWE-89",
                file_path=rel_path,
                line_start=start,
                line_end=end,
                code_snippet=text,
                snippet_start_line=first,
                explanation=(
                    f"In {where}, the SQL statement is built with {kind} and then passed to "
                    f"{call_name(node)}(). Any quote or SQL keyword inside the interpolated value becomes "
                    "part of the query itself instead of being treated as data."
                ),
                impact=(
                    "An attacker can change the meaning of the query, for example turning a filtered "
                    "search into 'return every row' or appending a UNION SELECT that reads other tables "
                    "such as user credentials."
                ),
                remediation=(
                    "Keep the SQL text constant and pass values separately as bound parameters, e.g. "
                    "db.execute(\"... WHERE title LIKE ?\", (f\"%{term}%\",)). The database driver then "
                    "treats the value strictly as data."
                ),
                detection_method=(
                    "Python AST analysis: located a DB-API execute() call whose first argument (directly or "
                    "via a local variable) is an f-string / concatenation / %-format / .format() containing "
                    "SQL keywords; traced interpolated variables one assignment back to request input."
                ),
                evidence={
                    "construction": kind,
                    "sink_line": node.lineno,
                    "sink_code": line_text(lines, node.lineno).strip(),
                    "query_line": query_line,
                    "query_code": line_text(lines, query_line).strip(),
                    "function": getattr(scope, "name", "<module>"),
                    "route": route[1] if route else None,
                    "interpolated_inputs": inputs,
                    "user_controlled": user_controlled,
                },
            ))
    return findings
