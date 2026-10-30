# Testing Contract: `testing/` ↔ backend

**Owner:** Dipto (runner, scenarios, PrivilegeMap, verdict rules, output schema).
**Consumer:** Diya's adapter, `backend/app/verification/adapter.py`.
The backend never imports `testing/` and never re-implements its tests. It runs the CLI below as a subprocess and validates the JSON it produces.

## Command

Run from the **repository root** (the `testing` package must be importable):

```powershell
# Single phase (used for the "baseline" exploit replay)
python -m testing.runner --scenario sqli --app-dir fixtures/vulnerable_app --phase baseline

# Before/after comparison with a Proof-of-Fix verdict (used for patch verification)
python -m testing.runner --scenario idor --original-dir <dir> --patched-dir <dir>

# Optional
--seed fixtures/seed/student_portal.sql    # SQL that builds the synthetic DB (default shown)
--output result.json                       # write JSON to a file instead of stdout (the backend uses this)
```

| Argument | Values |
|---|---|
| `--scenario` | `sqli`, `idor`, `all` |
| `--phase` | `baseline`, `before_patch`, `after_patch` (single-phase mode only) |
| `--app-dir` / `--original-dir` / `--patched-dir` | Any directory containing an `app.py` that defines `create_app(config: dict) -> Flask` and reads `config["DATABASE"]` |

**Exit codes:** `0` means the run completed (read the JSON, even if tests failed). `2` means bad arguments. `3` means an internal runner error (traceback on stderr).
A patched app that crashes on import is **not** exit 3. It is reported as `load_error` in that phase and leads to a `FAILED` verdict.

## Isolation guarantees (runner's responsibility)

- Each phase builds a **fresh SQLite file** in a temp dir from the seed SQL. The seed data is synthetic.
- Outbound IPv4/IPv6 socket connections are blocked for the whole process (`testing/harness.py: block_network`).
- Requests go through Flask's in-process test client, so no ports are opened.
- Each app copy is loaded under a unique module name, so the original and patched copies don't collide.
- The backend additionally runs the runner with a minimal environment (no `DATABASE_URL` or other secrets), a timeout (`VERIFICATION_TIMEOUT_SECONDS`, default 120), and on Linux/macOS CPU and memory rlimits. It always passes temp **copies** of the code, never the stored project.

## Output schema (`schema_version: "1.0"`)

```jsonc
{
  "schema_version": "1.0",
  "mode": "compare",                 // or "phase"
  "scenario": "idor",
  "generated_at": "2026-10-30T12:00:00+00:00",
  "phases": {                        // compare: before_patch + after_patch. phase: the one requested
    "before_patch": {
      "phase": "before_patch", "scenario": "idor", "app_dir": "C:\\…\\before",
      "started_at": "…", "duration_ms": 41,
      "load_error": null,            // string if app.py failed to import or create_app failed
      "exploit_reproduced": true,    // any security test with exploit_succeeded == true
      "security_tests":   { "total": 4, "passed": 0, "failed": 4, "errors": 0, "results": [ /* TestResult */ ] },
      "regression_tests": { "total": 4, "passed": 4, "failed": 0, "errors": 0, "results": [ /* TestResult */ ] }
    },
    "after_patch": { /* same shape */ }
  },
  "verdict": {                       // null in "phase" mode
    "status": "VERIFIED",            // VERIFIED | PARTIALLY_VERIFIED | FAILED
    "reasons": ["Original exploit reproduced before the patch", "…"],
    "original_vulnerability_reproduced": true,
    "exploit_blocked_after_patch": true,
    "regressions_pass_after_patch": true
  }
}
```

### TestResult

```jsonc
{
  "test_id": "sqli.tautology_leaks_private_docs",   // stable; the backend and frontend may reference it
  "scenario": "sqli",
  "category": "security",            // security = exploit attempt; regression = legitimate behaviour
  "name": "Tautology injection ( ' OR 1=1 -- )",
  "description": "…",
  "expected": "No private documents returned; HTTP 200 or 400",
  "status": "failed",                // passed | failed | error  (security: passed == exploit blocked)
  "actual": "Injection succeeded: private documents leaked ['Alice Private Diary', 'Bob Private Grades']",
  "exploit_succeeded": true,         // security tests: true/false. regression tests: null
  "evidence": {
    "request":  { "method": "GET", "path": "/search", "params": { "q": "' OR 1=1 --" }, "actor": "anonymous" },
    "response": { "status_code": 200, "body_excerpt": "[{\"id\":1,\"title\":\"Alice Private Diary\"}, …]" }
  },                                 // on status "error": { "traceback": "…" }
  "privilege_map": null              // IDOR tests: { rule_id, actor, resource, expected, observed, reason }
}
```

The backend validates `schema_version`, the required groups, integer counts, `total == len(results)`, both phases in compare mode, and that `verdict.status` is a known value. Anything else is treated as a runner error, which gives a `FAILED` verdict.

## Verdict rules (`testing/verdict.py`)

| Verdict | Condition |
|---|---|
| `VERIFIED` | Exploit reproduced **before** the patch, **and** every after-patch security test passed, **and** every after-patch regression test passed |
| `PARTIALLY_VERIFIED` | Every after-patch test passed, but the original exploit was **not** reproduced, so the fix can't be proven |
| `FAILED` | Any after-patch security or regression failure or error, any `load_error`, or an empty security or regression test set |

Missing tests are never counted as passing. The backend maps `VERIFIED → patch VERIFIED`, `FAILED → patch REJECTED`, and leaves `PARTIALLY_VERIFIED` as `APPLIED`.

## Current test inventory

**SQLi (`/search`)**
- Security: `sqli.tautology_leaks_private_docs`, `sqli.union_leaks_user_tokens`
- Regression: `sqli.search_finds_public_doc`, `sqli.empty_search_lists_public_docs`, `sqli.search_with_apostrophe`

**IDOR (`/documents/<id>`)**. These are generated from the PrivilegeMap in `testing/privilege_map.py`. DENY rules are security tests and ALLOW rules are regression tests.

| Rule | Actor | Document | Expected |
|---|---|---|---|
| alice_reads_own_doc | alice (student) | 1 (alice, private) | ALLOW |
| alice_reads_bob_doc | alice | 2 (bob, private) | DENY |
| bob_reads_alice_doc | bob | 1 | DENY |
| teacher_reads_assigned_student_doc | ms_rivera (teacher of alice) | 1 | ALLOW |
| teacher_reads_unassigned_student_doc | mr_okafor (no students) | 2 | DENY |
| anonymous_reads_private_doc | anonymous | 1 | DENY |
| anonymous_reads_public_doc | anonymous | 3 (public) | ALLOW |

There is also one extra regression test: `idor.owner_lists_own_documents`.

## Changing this contract

Adding new tests or scenarios is backwards compatible. Renaming `test_id`s, changing field names or types, or changing verdict rules requires bumping `schema_version` and telling Diya, who then updates the adapter's `SUPPORTED_SCHEMA`.
