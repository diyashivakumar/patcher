"""IDOR / broken object-level authorisation detector (CWE-639).

Supported pattern: a Flask-style route (`@app.route("/x/<id>")`, `@bp.get(...)`)
whose URL contains a path parameter, which
  1. passes that parameter into a data lookup (execute/query/get/fetch/find/filter...),
  2. and never performs an authorisation decision on the result.

An authorisation decision is any of:
  * a call to a helper whose name looks like an access check
    (can_*, *authori[sz]e*, *permission*, has_access, check_access, is_owner, ...),
  * a decorator with such a name,
  * a comparison involving an ownership field (owner, user_id, author, created_by),
  * a lookup whose SQL already filters on an ownership column.

This is a structural heuristic, not a proof. It is precise for the supported
pattern and documented as such; it does not understand custom middleware.
"""
import ast
import re

from app.scanner.common import FindingData, call_name, iter_scopes, line_text, route_info, scope_nodes, snippet

AUTHZ_NAME = re.compile(
    r"(^can_|authori[sz]|permission|has_access|check_access|is_owner|owns|require_owner|"
    r"ensure_owner|verify_access|allowed)", re.IGNORECASE)
OWNERSHIP = re.compile(r"(owner|user_id|author|created_by)", re.IGNORECASE)
LOOKUP_NAME = re.compile(r"(execute|query|get|fetch|find|filter|select|load)", re.IGNORECASE)
CURRENT_USER = re.compile(r"current_user", re.IGNORECASE)


OWNER_FILTER_SQL = re.compile(r"\bWHERE\b.*\b(owner\w*|user_id|author\w*|created_by)\s*=", re.IGNORECASE | re.DOTALL)


def lookup_scoped_to_owner(call):
    """True if the lookup itself filters by owner (SQL WHERE owner_id = ? or filter_by(owner_id=...))."""
    for kw in call.keywords:
        if kw.arg and OWNERSHIP.search(kw.arg):
            return True
    for n in ast.walk(call):
        if isinstance(n, ast.Constant) and isinstance(n.value, str) and OWNER_FILTER_SQL.search(n.value):
            return True
    return False


def _mentions_ownership(node):
    for n in ast.walk(node):
        if isinstance(n, ast.Attribute) and OWNERSHIP.search(n.attr):
            return True
        if isinstance(n, ast.Constant) and isinstance(n.value, str) and OWNERSHIP.search(n.value):
            return True
    return False


def _is_unconditional_deny(stmt):
    """A top-level `abort(401|403)` or `raise Forbidden(...)` in the route body: nobody gets through."""
    if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call) and call_name(stmt.value) == "abort":
        args = stmt.value.args
        return bool(args) and isinstance(args[0], ast.Constant) and args[0].value in (401, 403)
    return isinstance(stmt, ast.Raise) and stmt.exc is not None and "Forbidden" in ast.dump(stmt.exc)


def has_authorization(func):
    if any(_is_unconditional_deny(stmt) for stmt in func.body):
        return True
    for dec in func.decorator_list:
        target = dec.func if isinstance(dec, ast.Call) else dec
        name = target.attr if isinstance(target, ast.Attribute) else getattr(target, "id", "")
        if AUTHZ_NAME.search(name):
            return True
    for node in scope_nodes(func):
        if isinstance(node, ast.Call) and AUTHZ_NAME.search(call_name(node)):
            return True
        if isinstance(node, ast.Compare) and _mentions_ownership(node):
            return True
    return False


def find_lookup(func, params):
    """Return (call_node, statement_node, assigned_name) for the first lookup using a path param."""
    for stmt in func.body:
        for node in ast.walk(stmt):
            if not (isinstance(node, ast.Call) and LOOKUP_NAME.search(call_name(node))):
                continue
            arg_names = {n.id for a in list(node.args) + [k.value for k in node.keywords]
                         for n in ast.walk(a) if isinstance(n, ast.Name)}
            if not arg_names & set(params):
                continue
            target = None
            if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 and isinstance(stmt.targets[0], ast.Name):
                target = stmt.targets[0].id
            return node, stmt, target
    return None


def find_current_user_var(func):
    for stmt in func.body:
        if (isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 and isinstance(stmt.targets[0], ast.Name)
                and isinstance(stmt.value, ast.Call) and CURRENT_USER.search(call_name(stmt.value))):
            return stmt.targets[0].id, stmt.lineno
    return None, None


def authz_helpers(tree):
    """Functions anywhere in the module that look like access-check helpers taking (user, resource)."""
    helpers = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and AUTHZ_NAME.search(node.name):
            args = [a.arg for a in node.args.args]
            if len(args) == 2:
                helpers.append({"name": node.name, "args": args, "line": node.lineno})
    return helpers


def detect(tree, lines, rel_path):
    findings = []
    helpers = authz_helpers(tree)
    for func in iter_scopes(tree):
        if not isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        route = route_info(func)
        if not route or not route[2]:
            continue
        decorator, path, params = route
        lookup = find_lookup(func, params)
        if not lookup:
            continue
        call, stmt, resource_var = lookup
        if lookup_scoped_to_owner(call) or has_authorization(func):
            continue

        user_var, user_line = find_current_user_var(func)
        end_line = func.end_lineno
        text, first = snippet(lines, decorator.lineno, end_line, context=0)
        helper_note = (
            f" An access-check helper ({', '.join(h['name'] for h in helpers)}) exists in this module "
            "but this route never calls it."
            if helpers else ""
        )
        findings.append(FindingData(
            vuln_type="idor",
            title="Broken access control (IDOR) on object lookup",
            severity="HIGH",
            severity_rationale=(
                "Any caller can read another user's private record by changing an identifier in the URL. "
                "No special privileges or user interaction are needed and confidentiality impact is high; "
                "rated HIGH rather than CRITICAL because it exposes records one at a time and does not "
                "allow arbitrary query execution."
            ),
            confidence="HIGH" if helpers else "MEDIUM",
            cwe="CWE-639",
            file_path=rel_path,
            line_start=decorator.lineno,
            line_end=end_line,
            code_snippet=text,
            snippet_start_line=first,
            explanation=(
                f"Route {path} loads a record using the client-supplied '{', '.join(params)}' value "
                f"(line {stmt.lineno}) and returns it without checking whether the current user is allowed "
                f"to see that record.{helper_note}"
            ),
            impact=(
                "Insecure Direct Object Reference: a student can read another student's private documents "
                "simply by iterating document IDs, and anonymous callers can read private data."
            ),
            remediation=(
                "After loading the record, enforce a server-side authorisation rule (owner, assigned "
                "teacher, or public) and return 403 when it fails. Never rely on the client to only request "
                "IDs it is allowed to see."
            ),
            detection_method=(
                "Python AST analysis: found a route with a URL path parameter that is passed into a data "
                "lookup, with no access-check helper call, authorisation decorator, ownership comparison or "
                "ownership-filtered query in the route body."
            ),
            evidence={
                "function": func.name,
                "function_line": func.lineno,
                "route": path,
                "route_line": decorator.lineno,
                "path_params": params,
                "lookup_line": stmt.lineno,
                "lookup_code": line_text(lines, stmt.lineno).strip(),
                "resource_variable": resource_var,
                "current_user_variable": user_var,
                "current_user_line": user_line,
                "available_authz_helpers": helpers,
            },
        ))
    return findings
