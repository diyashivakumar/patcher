"""Shared AST helpers and the FindingData structure produced by every detector."""
import ast
import re
from dataclasses import dataclass, field

ROUTE_METHODS = {"route", "get", "post", "put", "patch", "delete"}
PATH_PARAM_RE = re.compile(r"<(?:[^:<>]+:)?([A-Za-z_][A-Za-z0-9_]*)>")


@dataclass
class FindingData:
    vuln_type: str
    title: str
    severity: str
    severity_rationale: str
    confidence: str
    cwe: str
    file_path: str
    line_start: int
    line_end: int
    code_snippet: str
    snippet_start_line: int
    explanation: str
    impact: str
    remediation: str
    detection_method: str
    evidence: dict = field(default_factory=dict)


def iter_scopes(tree):
    """Yield the module and every function (including nested ones) as separate scopes."""
    yield tree
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            yield node


def scope_nodes(scope):
    """Walk a scope's body without descending into nested functions or classes."""
    nested = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)
    stack = [n for n in scope.body if not isinstance(n, nested)]
    while stack:
        node = stack.pop()
        yield node
        stack.extend(c for c in ast.iter_child_nodes(node) if not isinstance(c, nested))


def call_name(call):
    """'execute' for db.execute(...), 'query_one' for query_one(...)."""
    func = call.func
    if isinstance(func, ast.Attribute):
        return func.attr
    if isinstance(func, ast.Name):
        return func.id
    return ""


def route_info(func):
    """Return (decorator_node, path, [path params]) if func is a Flask-style route, else None."""
    for dec in func.decorator_list:
        if (isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute)
                and dec.func.attr in ROUTE_METHODS and dec.args
                and isinstance(dec.args[0], ast.Constant) and isinstance(dec.args[0].value, str)):
            path = dec.args[0].value
            return dec, path, PATH_PARAM_RE.findall(path)
    return None


def names_in(node):
    return {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}


def line_text(lines, lineno):
    return lines[lineno - 1].rstrip("\n") if 0 < lineno <= len(lines) else ""


def snippet(lines, start, end, context=2):
    """Return (text, first_line_number) covering [start, end] plus context lines."""
    first = max(1, start - context)
    last = min(len(lines), end + context)
    return "".join(lines[first - 1:last]).rstrip("\n"), first
