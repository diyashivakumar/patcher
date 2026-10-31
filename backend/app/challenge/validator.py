"""AST Safety Gate for untrusted AI-generated and user-submitted patches.

Before candidate code is allowed to reach the temporary fixture runner, it must pass
strict AST validation:
  1. Contains exactly the replacement function.
  2. Function name and signature match the expected contract.
  3. No additional top-level statements, functions, classes or imports.
  4. No forbidden functions (eval, exec, open, __import__, compile, globals, locals).
  5. No dangerous module usage (os, sys, subprocess, socket, etc.).
  6. No import statements inside the function body.
"""
import ast
from app.challenge.schemas import SafetyValidationResult

FORBIDDEN_CALLS = {
    "eval",
    "exec",
    "open",
    "__import__",
    "compile",
    "globals",
    "locals",
    "getattr",
    "setattr",
    "delattr",
}

FORBIDDEN_MODULES = {
    "os",
    "sys",
    "subprocess",
    "socket",
    "pty",
    "shutil",
    "importlib",
    "ctypes",
    "signal",
    "multiprocessing",
    "threading",
    "asyncio",
    "pathlib",
}

FORBIDDEN_ATTRIBUTES = {
    "__subclasses__",
    "__globals__",
    "__code__",
    "__builtins__",
    "__mro__",
    "__class__",
    "__dict__",
}


def validate_candidate_ast(
    source_code: str,
    expected_function_name: str,
    expected_args: list[str] | None = None,
) -> SafetyValidationResult:
    """Validate candidate Python source code.
    
    Returns SafetyValidationResult with valid=True if code adheres to the strict contract,
    or valid=False with a clear rejection reason.
    """
    clean_code = source_code.strip()
    if not clean_code:
        return SafetyValidationResult(valid=False, rejection_reason="Candidate code is empty.")

    try:
        tree = ast.parse(clean_code)
    except SyntaxError as exc:
        return SafetyValidationResult(
            valid=False,
            rejection_reason=f"Syntax error in candidate code (line {exc.lineno}): {exc.msg}",
        )

    # Must contain exactly one top-level statement which must be a FunctionDef
    if len(tree.body) != 1:
        types = [type(n).__name__ for n in tree.body]
        return SafetyValidationResult(
            valid=False,
            rejection_reason=f"Candidate must define exactly one function. Found {len(tree.body)} statements: {types}",
        )

    func = tree.body[0]
    if not isinstance(func, ast.FunctionDef):
        return SafetyValidationResult(
            valid=False,
            rejection_reason=f"Expected function definition, found {type(func).__name__}.",
        )

    # Check function name
    if func.name != expected_function_name:
        return SafetyValidationResult(
            valid=False,
            rejection_reason=f"Function name '{func.name}' does not match expected '{expected_function_name}'.",
            function_name=func.name,
        )

    # Check arguments
    arg_names = [a.arg for a in func.args.args]
    if expected_args is not None:
        if arg_names != expected_args:
            return SafetyValidationResult(
                valid=False,
                rejection_reason=f"Function arguments {arg_names} do not match expected {expected_args}.",
                function_name=func.name,
            )

    # Decorator checks: if decorated, only allow @app.route
    for dec in func.decorator_list:
        if isinstance(dec, ast.Call):
            if isinstance(dec.func, ast.Attribute) and dec.func.attr == "route":
                continue
        return SafetyValidationResult(
            valid=False,
            rejection_reason="Unexpected or unsupported decorator on replacement function.",
            function_name=func.name,
        )

    # Inspect all AST nodes in the function body for forbidden constructs
    inspected: list[str] = []
    for node in ast.walk(func):
        # Disallow any import statements
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            names = []
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            else:
                names = [f"{node.module}.{alias.name}" for alias in node.names]
            return SafetyValidationResult(
                valid=False,
                rejection_reason=f"Forbidden import statement: {names}",
                function_name=func.name,
            )

        # Disallow forbidden function calls
        if isinstance(node, ast.Call):
            called_name = None
            if isinstance(node.func, ast.Name):
                called_name = node.func.id
            elif isinstance(node.func, ast.Attribute):
                called_name = node.func.attr
                # Check if called on a forbidden module
                if isinstance(node.func.value, ast.Name) and node.func.value.id in FORBIDDEN_MODULES:
                    return SafetyValidationResult(
                        valid=False,
                        rejection_reason=f"Forbidden call to module '{node.func.value.id}.{called_name}'.",
                        function_name=func.name,
                    )

            if called_name:
                inspected.append(called_name)
                if called_name in FORBIDDEN_CALLS:
                    return SafetyValidationResult(
                        valid=False,
                        rejection_reason=f"Forbidden function call '{called_name}'.",
                        function_name=func.name,
                    )

        # Disallow attribute access to dangerous names / dunders
        if isinstance(node, ast.Attribute):
            if node.attr in FORBIDDEN_ATTRIBUTES:
                return SafetyValidationResult(
                    valid=False,
                    rejection_reason=f"Forbidden attribute access '{node.attr}'.",
                    function_name=func.name,
                )
            if isinstance(node.value, ast.Name) and node.value.id in FORBIDDEN_MODULES:
                return SafetyValidationResult(
                    valid=False,
                    rejection_reason=f"Forbidden access to module '{node.value.id}'.",
                    function_name=func.name,
                )

        # Disallow Name access to forbidden modules directly
        if isinstance(node, ast.Name) and node.id in FORBIDDEN_MODULES:
            return SafetyValidationResult(
                valid=False,
                rejection_reason=f"Forbidden reference to module '{node.id}'.",
                function_name=func.name,
            )

    return SafetyValidationResult(
        valid=True,
        function_name=func.name,
        inspected_constructs=list(set(inspected))[:10],
    )

