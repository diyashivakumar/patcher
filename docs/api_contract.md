# PatchProof API Contract

**Owner:** Diya (backend). **Consumers:** Chinmayee (frontend), Dipto (testing, read-only).
**Rule:** Response shapes below are frozen. Any change must be announced to both teammates and updated here *before* merging.

- Base URL (dev): `http://localhost:8000/api`
- Interactive docs (generated from the code, always current): `http://localhost:8000/docs`
- Machine-readable schema: `http://localhost:8000/openapi.json`
- Pydantic source of truth: `backend/app/schemas/`; TypeScript mirror: `frontend/src/types/api.ts`
- IDs are UUID strings. Timestamps are ISO-8601 with timezone.

## Error format (every endpoint)

```json
{ "error": { "code": "not_found", "message": "Project not found", "details": null } }
```

| Status | `code` values | Meaning |
|---|---|---|
| 403 | `approval_required` | Tried to apply a patch without `approved: true` |
| 404 | `not_found` | Unknown id |
| 409 | `invalid_state`, `patch_conflict`, `rollback_conflict`, `patch_already_applied`, `source_changed`, `source_unavailable`, `verification_not_possible` | Action not allowed in the current state |
| 422 | `validation_error` (details = list of `{loc, msg}`), `unknown_fixture`, `upload_rejected`, `invalid_upload`, `patch_not_supported` | Bad input, or the code shape is outside the auto-patcher's scope |
| 500 | `fixture_unavailable` | Bundled fixture files are missing on the server |
| 503 | `database_not_configured` | `DATABASE_URL` missing or not PostgreSQL |

---

## Health & dashboard

### `GET /health` → 200
```json
{ "status": "ok", "database": "ok", "version": "0.1.0" }
```
`status` is `"degraded"` and `database` is `"error: <ExceptionName>"` if Neon is unreachable.

### `GET /health/ollama` → 200 (always; never fails)
```json
{ "available": false, "base_url": "http://localhost:11434", "model": "llama3.2",
  "model_installed": false, "installed_models": [],
  "message": "Ollama is not reachable at http://localhost:11434 (ConnectError). PatchProof works fully without it." }
```

### `GET /dashboard/summary` → 200
Real database counts only.
```json
{
  "total_projects": 1, "total_scans": 1, "total_findings": 2,
  "findings_by_severity": { "CRITICAL": 1, "HIGH": 1, "MEDIUM": 0, "LOW": 0 },
  "patches_generated": 3, "patches_verified": 2, "patches_rejected": 0,
  "verification_runs_by_verdict": { "VERIFIED": 2, "PARTIALLY_VERIFIED": 0, "FAILED": 1 },
  "recent_scans": [ { "id": "…", "project_id": "…", "project_name": "Student Portal Demo",
                      "status": "COMPLETED", "findings_count": 2, "started_at": "…" } ]
}
```
`patches_verified` / `patches_rejected` count patches **currently** in that state (a rejected patch that was rolled back counts as `ROLLED_BACK`). The verification history is in `verification_runs_by_verdict`.

---

## Projects

### `GET /fixtures` → 200
```json
[ { "name": "student_portal", "title": "Student Document Portal (deliberately vulnerable)",
    "description": "…", "verification_scenarios": ["sqli", "idor"] } ]
```

### `POST /projects` → 201 `ProjectDetail`
Creates a project by copying a bundled fixture.
```json
{ "name": "Student Portal Demo", "description": "optional", "fixture_name": "student_portal" }
```
Errors: 422 `unknown_fixture`.

### `POST /projects/upload` → 201 `ProjectDetail`
`multipart/form-data` fields: `name` (required), `description` (optional), `file` (required, `.zip`).
Limits: ≤ 10 MB ZIP, ≤ 50 MB extracted, ≤ 2000 files, compression ratio ≤ 100, must contain `.py` files.
Rejected outright (422 `upload_rejected`): path traversal (`../`, absolute, drive letters), symlinks, ZIP bombs, oversize, non-ZIP.
Silently **skipped** and listed in `upload_skipped`: `.env*`, `*.pem`, `*.key`, `id_rsa*`, `secrets.*`, disallowed file types, `.git/`, `venv/`, `node_modules/`, `__pycache__/`.

### `GET /projects` → 200 `Project[]`

### `GET /projects/{project_id}` → 200 `ProjectDetail`

```json
{
  "id": "…", "name": "Student Portal Demo", "description": null,
  "source_type": "fixture", "fixture_name": "student_portal",
  "file_count": 2, "total_bytes": 3912,
  "verification_supported": true, "verification_scenarios": ["sqli", "idor"],
  "scan_count": 1, "latest_scan": { "…ScanSummary…" },
  "created_at": "…", "updated_at": "…",
  "scans": [ "…ScanSummary, newest first…" ],
  "upload_skipped": [ { "path": "svc/.env", "reason": "possible secret file; not stored" } ]
}
```
`Project` (list item) is the same without `scans` and `upload_skipped`. Uploaded projects have `verification_supported: false`.

---

## Scans

### `POST /scans` → 201 `ScanSummary`
```json
{ "project_id": "…" }
```
Runs synchronously on the project's **current working copy**, so a re-scan after applying a patch reflects the patch.

### `GET /scans/{scan_id}` → 200 `ScanSummary`
```json
{
  "id": "…", "project_id": "…", "status": "COMPLETED",
  "started_at": "…", "completed_at": "…", "files_scanned": 1, "findings_count": 2,
  "severity_counts": { "CRITICAL": 1, "HIGH": 1, "MEDIUM": 0, "LOW": 0 },
  "warnings": [], "error": null
}
```
`status`: `RUNNING | COMPLETED | FAILED`. `warnings` lists skipped files, such as syntax errors.

### `GET /scans/{scan_id}/findings` → 200 `Finding[]` (ordered by line)

---

## Findings

### `GET /findings/{finding_id}` → 200 `FindingDetail`
```json
{
  "id": "…", "scan_id": "…", "project_id": "…",
  "vuln_type": "sqli", "title": "SQL injection via string-built query",
  "severity": "CRITICAL", "severity_rationale": "HTTP request input flows directly…",
  "confidence": "HIGH", "cwe": "CWE-89",
  "file_path": "app.py", "line_start": 68, "line_end": 69,
  "code_snippet": "    def search():\n        term = …", "snippet_start_line": 66,
  "evidence": {
    "construction": "f-string", "sink_line": 69, "sink_code": "rows = get_db().execute(sql).fetchall()",
    "query_line": 68, "query_code": "sql = f\"SELECT …\"", "function": "search", "route": "/search",
    "interpolated_inputs": [ { "name": "term", "source": "term = request.args.get(\"q\", \"\")", "line": 67, "user_controlled": true } ],
    "user_controlled": true
  },
  "explanation": "…", "impact": "…", "remediation": "…", "detection_method": "…",
  "created_at": "…",
  "patches": [ { "id": "…", "strategy": "parameterized_query", "status": "VERIFIED", "created_at": "…" } ],
  "available_strategies": ["parameterized_query"],
  "verification_supported": true
}
```
The `evidence` keys differ by `vuln_type`. For IDOR they are `function`, `function_line`, `route`, `route_line`, `path_params`, `lookup_line`, `lookup_code`, `resource_variable`, `current_user_variable`, `current_user_line` and `available_authz_helpers[]`. `Finding` (list item) has the same fields without the last three.

### `POST /findings/{finding_id}/ai-explanation` → 200 (always)
Optional and advisory. Never used for detection, severity, patching or verdicts.
```json
{ "available": false, "model": null, "text": null,
  "message": "Ollama is not reachable …", "advisory": "AI-generated, advisory only. …" }
```

---

## Patches

Status flow: `PROPOSED → APPLIED → VERIFIED | REJECTED`, then `APPLIED | VERIFIED | REJECTED → ROLLED_BACK`.
A `PARTIALLY_VERIFIED` verdict leaves the patch `APPLIED` for human review.

### `POST /patches/generate` → 201 `Patch`
```json
{ "finding_id": "…", "strategy": null }
```
Strategies: `sqli` → `parameterized_query` (default). `idor` → `ownership_check` (default) or `deny_all_demo` (a deliberately bad demo patch).
Nothing on disk changes. Errors: 409 `patch_already_applied` (roll back the active patch first; `details.patch_id`), 422 `patch_not_supported` (e.g. `%`-formatted SQL, no access-check helper in the module).

### `GET /patches/{patch_id}` → 200 `Patch`
```json
{
  "id": "…", "finding_id": "…", "project_id": "…", "vuln_type": "sqli",
  "strategy": "parameterized_query", "is_demo_bad_patch": false, "status": "PROPOSED",
  "file_path": "app.py", "line_start": 68, "line_end": 69,
  "original_snippet": "        sql = f\"…\"\n        rows = get_db().execute(sql).fetchall()\n",
  "patched_snippet": "        sql = \"… LIKE ?\"\n        rows = get_db().execute(sql, (f\"%{term}%\",)).fetchall()\n",
  "diff": "--- a/app.py\n+++ b/app.py\n@@ -65,8 +65,8 @@ …",
  "rationale": "The SQL text is now a constant …",
  "validation": { "syntax_ok": true, "target_finding_cleared": true, "remaining_findings_in_file": 1,
                  "note": "Static re-scan of the patched file. This is not verification; …" },
  "approved_by": null, "approved_at": null, "applied_at": null, "rolled_back_at": null,
  "created_at": "…",
  "verification_runs": [ { "id": "…", "kind": "proof_of_fix", "status": "COMPLETED", "verdict": "VERIFIED", "created_at": "…" } ]
}
```

### `POST /patches/{patch_id}/apply` → 200 `Patch`
```json
{ "approved": true, "approved_by": "diya" }
```
Backs up the file first, then applies the change to the project's working copy. Errors: 403 `approval_required`, 409 `invalid_state` (not `PROPOSED`), 409 `patch_conflict` (the file changed).

### `POST /patches/{patch_id}/rollback` → 200 `Patch`
```json
{ "reason": "Rejected by Proof-of-Fix", "requested_by": "diya" }
```
Both fields are optional. Reverses exactly this patch and leaves other applied patches in place. Errors: 409 `invalid_state`, `rollback_conflict`.

---

## Verification

### `POST /verification/run` → 201 `VerificationRunDetail`
Use one of two modes:
```json
{ "patch_id": "…" }                                   // Proof-of-Fix: original vs patched copy
{ "project_id": "…", "scenario": "sqli" }             // Baseline: replay the exploit on the original code
```
Proof-of-Fix requires the patch to be applied (`APPLIED | VERIFIED | REJECTED`). Verification runs only for fixture projects.
Errors: 409 `verification_not_possible`, 422 `validation_error`.
If the runner itself fails (timeout, crash, malformed output), the run is stored with `status: "ERROR"` and `verdict: "FAILED"`, and the patch status is unchanged.

### `GET /verification/{run_id}` → 200 `VerificationRunDetail`
```json
{
  "id": "…", "project_id": "…", "patch_id": "…", "kind": "proof_of_fix", "scenario": "idor",
  "status": "COMPLETED", "verdict": "FAILED",
  "verdict_reasons": ["after_patch: regression tests failing (legitimate behaviour broken): ['idor.alice_reads_own_doc', …]"],
  "original_vulnerability_reproduced": true, "exploit_blocked_after_patch": true, "regressions_pass_after_patch": false,
  "phase_summaries": {
    "before_patch": { "exploit_reproduced": true, "load_error": null, "duration_ms": 40,
                      "security_tests": { "total": 4, "passed": 0, "failed": 4, "errors": 0 },
                      "regression_tests": { "total": 4, "passed": 4, "failed": 0, "errors": 0 } },
    "after_patch":  { "…": "…" }
  },
  "error": null, "started_at": "…", "completed_at": "…", "duration_ms": 545, "created_at": "…",
  "patch_status": "REJECTED",
  "test_results": [
    { "phase": "after_patch", "category": "regression", "test_id": "idor.alice_reads_own_doc",
      "name": "alice -> document 1: expect ALLOW", "description": "Students may read their own documents.",
      "status": "failed", "expected": "ALLOW", "actual": "DENY (HTTP 403)", "exploit_succeeded": null,
      "evidence": { "request": { "method": "GET", "path": "/documents/1", "params": {}, "actor": "alice" },
                    "response": { "status_code": 403, "body_excerpt": "…" } },
      "privilege_map": { "rule_id": "alice_reads_own_doc", "actor": "alice", "resource": "document:1",
                         "expected": "ALLOW", "observed": "DENY", "reason": "…" } }
  ]
}
```
For a baseline run, `kind` is `"baseline"`, `verdict` is `null`, `phase_summaries` has the single key `baseline`, and `original_vulnerability_reproduced` holds the result.

### `GET /verification?project_id=&patch_id=&kind=` → 200 `VerificationRun[]`
Newest first, at most 100. Same shape as above without `patch_status` and `test_results`.

---

## Reports

`report_id` is the verification run id.

### `GET /reports` → 200
```json
[ { "report_id": "…", "kind": "proof_of_fix", "scenario": "sqli", "status": "COMPLETED", "verdict": "VERIFIED",
    "original_vulnerability_reproduced": true, "project_id": "…", "patch_id": "…",
    "patch_strategy": "parameterized_query", "created_at": "…" } ]
```

### `GET /reports/{report_id}?format=json|html` → 200
`json` (default) returns the project, scan, finding (with severity rationale and evidence), patch (rationale, diff, approver), verification (verdict, reasons, all executed tests with evidence) and `known_limitations`.
`html` returns a self-contained printable page served with `Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'`.
