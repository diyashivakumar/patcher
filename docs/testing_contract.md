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
- Outbound IPv4/IPv6 traffic is blocked for the whole process (`testing/harness.py: block_network`): `connect`, `connect_ex`, `sendto`, `sendmsg`, `create_connection` and DNS resolution (`getaddrinfo`, `gethostbyname*`). This is an in-process guard for trusted fixture code, not an OS sandbox.
- Requests go through Flask's in-process test client, so no ports are opened.
- Each app copy is loaded under a unique module name, so the original and patched copies don't collide.
- The backend additionally runs the runner with a minimal environment (no `DATABASE_URL` or other secrets), a timeout (`VERIFICATION_TIMEOUT_SECONDS`, default 120), and on Linux/macOS CPU and memory rlimits. It always passes temp **copies** of the code, never the stored project.

## Output schema (`schema_version: "1.1"`; 1.1 additions are described at the end)

```jsonc
{
  "schema_version": "1.1",
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

Adding new tests or scenarios is backwards compatible. Renaming `test_id`s, changing field names or types, or changing verdict rules requires bumping `schema_version` and telling Diya, who then updates the adapter's `SUPPORTED_SCHEMAS` (currently 1.0 and 1.1).

---

## Schema 1.1: Exploit Variant Gauntlet + Data Exposure Forensics

> **For Dipto's review.** These changes were made in `testing/` and `fixtures/` with Diya's explicit authorisation, kept additive, and verified with the full suite (31 tests pass, including the original 13 with the same test IDs). Please review before relying on them. Section "Changes to Dipto-owned files" below lists every edit.

### Canary record format (`fixtures/seed/student_portal.sql`, registry in `testing/canaries.py`)
Three private, fabricated documents. Each **field** carries its own marker, so inspection proves which record *and* which field was returned:

| record_id | db id | owner | authorised readers | title marker | body marker |
|---|---|---|---|---|---|
| DOC-101 | 101 | alice | alice, ms_rivera | `CANARY-STUDENT-A-101:TITLE` | `CANARY-STUDENT-A-101:BODY` |
| DOC-202 | 202 | bob | bob | `CANARY-STUDENT-B-202:TITLE` | `CANARY-STUDENT-B-202:BODY` |
| DOC-303 | 303 | carol (new student) | carol | `CANARY-STUDENT-C-303:TITLE` | `CANARY-STUDENT-C-303:BODY` |

Sensitivity: `title` = confidential, `body` = restricted. Markers match `CANARY-STUDENT-[A-Z]-\d{3}(:FIELD)?`. All records have `is_public = 0`, so public-search regression tests are unaffected.

### Response inspection (`testing/forensics.py`)
Exposure is decided **only** from markers present in the actual body. The status code is recorded but never decides on its own. A 403 whose body contains a marker counts as exposed; a 200 with no marker does not.
Request outcome: `rejected` | `accepted_no_protected_data` | `protected_record_exposed` | `partial_field_exposure` | `multiple_records_exposed` | `inconclusive` (5xx or harness error with no markers).
Record status: `protected_record_exposed` (all fields) | `partial_field_exposure` | `authorized_access` (the actor may read it).
Evidence kept: matched markers, field names, actor, request line, status code and response size. **Bodies are never stored.**

### Variants (`testing/gauntlet.py`)
Built-in, fixed and harmless (GET only, read-only):
- **SQLi:** `original`, `whitespace`, `case`, `inline_comment`, `url_encoded`, `double_url_encoded` (expected INVALID), `position_reopen`, `union_body`, plus legit `legit_keyword` and `legit_apostrophe`.
- **IDOR:** A→B, A→C, B→A, C→B, unassigned teacher, other teacher, anonymous→A, anonymous→C, leading-zero id, plus legit A/B/C own records and the assigned teacher.

A variant is `exploited` when its actual response shows any of:
- **canary markers** of a protected record (`detection: "canary_marker"`);
- **record identity**: an unauthorised actor received the requested canary record's own `id` with a 2xx response, even if its fields were transformed (`detection: "record_identity"`, `exposure_status: "record_returned_markers_not_visible"`);
- **an injection probe** (SQLi attack variants with a `check`): `{"type": "union_marker", "marker": "PPROOF-PROBE-…"}` (a UNION constant appears in a result row), or `{"type": "rows_with_ids", "ids": [3]}` (rows come back for a literal term that matches nothing). The outcome is `injection_executed` and the phase view sets `injection_probe_hit: true`.

The identity and probe oracles were added after QA showed that a patch which only filtered or encoded the marked data was wrongly VERIFIED (docs/FINAL_QA_REPORT.md, QA-1 and QA-2). Built-in probes: `sqli.gv.union_probe` and `sqli.gv.boolean_probe`.

Differential classification (compare mode):

| kind | before (original) | after (patched) | status |
|---|---|---|---|
| attack | not exploited | any | `invalid` (never counted as a block) |
| attack | exploited | exploited | `bypass` |
| attack | exploited | errored / 5xx, no data | `inconclusive` |
| attack | exploited | not exploited | `blocked` |
| legit | any | expected data returned | `works` |
| legit | any | otherwise | `regression_failed` |

### Output additions (schema 1.1, additive)
- Every phase gets `variants: [VariantResult]` and `exposures: [LedgerRow]`.
- Compare mode adds:
  - `gauntlet: {cases, counts, valid_attack_variants, bypasses, requires_review}`
  - `forensics: {canary_records, phases: {before_patch, after_patch}, comparison}`
- Phase mode adds `forensics` with one phase.
- Each `forensics.phases.<phase>` holds `unauthorized_records_exposed`, `protected_fields_exposed`, `legitimate_records_accessible`, `exposure_events` and `ledger`.
- `comparison` holds `records_no_longer_exposed`, `records_still_exposed`, `fields_no_longer_exposed`, `fields_still_exposed`, `legitimate_access_kept` and `legitimate_access_lost`.

`LedgerRow` fields: `phase, scenario, evidence_ref, variant_id, actor, request, status_code, record_id, record_owner, record_type, authorized, exposed_fields, field_sensitivity, canary_match, exposure_status`. The backend adds `verification_run_id`.

### Verdict integration (`testing/verdict.py`)
`compute_verdict(before, after, gauntlet=None)`. With a gauntlet:
- any `bypass` → **FAILED**
- any `regression_failed` → **FAILED**
- `inconclusive` can only downgrade VERIFIED to PARTIALLY_VERIFIED
- `invalid` never helps

`exploit_blocked_after_patch` is false while any bypass survives. The verdict gains `gauntlet_bypasses`. The verdict is still computed **only** here.

### Saved regression cases (`--extra-variants file.json`)
- The backend writes previously confirmed bypasses, taken from its `regression_cases` table, to a temp JSON list. Each item: `{scenario, kind, variation, description, input, check, regression_case_id}`.
- The runner **re-validates every item** before running anything:
  - GET only;
  - known synthetic actors only;
  - `/search` or `/documents/<id>` only;
  - exactly one `q` parameter (also inside `raw_query`), at most 200 chars;
  - attack oracles limited to `union_marker` (marker `^PPROOF-PROBE-[A-Z0-9-]{1,40}$`) and `rows_with_ids` (positive ints); legit checks limited to `authorized_record` and `public_titles`;
  - no state-changing SQL keywords and no `;`.
- Invalid input exits with code 2.
- An item identical to a built-in variant (same fingerprint) is linked through `regression_case_id` rather than duplicated. A new one runs as `<scenario>.saved.<fingerprint8>`.

### Changes to Dipto-owned files (please review)
| File | Change |
|---|---|
| `fixtures/seed/student_portal.sql` | + user `carol` (id 5, token `tok-carol-SYNTHETIC`); + private canary docs 101/202/303 |
| `fixtures/variants/naive_blocklist/app.py` | new reference variant: rejects only `' OR 1=1` (must be REJECTED) |
| `testing/canaries.py`, `testing/forensics.py`, `testing/gauntlet.py` | new modules |
| `testing/runner.py` | schema 1.1, runs variants in the same isolated client, `--extra-variants` |
| `testing/verdict.py` | optional `gauntlet` argument (rules above) |
| `testing/harness.py` | + actor `carol` |
| `testing/scenarios/idor.py` | `idor.owner_lists_own_documents` now expects `[1, 101]` (alice owns DOC-101). Same test_id. |
| `testing/tests/test_runner.py` | CLI test expects schema `1.1` |
| `testing/tests/test_gauntlet_forensics.py` | 18 new tests |

---

## `chain` scenario (composed kill-chain)

`testing/scenarios/chain.py` composes the **existing** SQLi and IDOR steps — it adds no new attack payload.

Steps (each runs only if the previous was reached):
1. `chain.sqli_token_theft` — the existing UNION step (`' UNION SELECT id, api_token FROM users --`); parse which synthetic `tok-…-SYNTHETIC` tokens leaked (matched against `harness.ACTORS`).
2. `chain.token_replay` — replay one stolen token as `X-User-Token` (the header `harness.call` already sends); confirm the app accepts it.
3. `chain.idor_document_walk` — with that token, GET each canary document; record cross-user exposure via `forensics.inspect` (reused oracle), excluding records the actor is authorised for.

Run it like any scenario: `python -m testing.runner --scenario chain --app-dir <dir> --phase before_patch`. It also runs in `before_patch`/`after_patch` phases. `chain` is **not** part of `all`, and the gauntlet builds no variants for it (`variants_for("chain") == []`), so the Proof-of-Fix verdict flow is unchanged.

The chain is one SECURITY `TestCase`; its per-step detail and ledger ride in that result's `evidence["chain"]`:
```jsonc
{ "steps": [ { "step_id", "name", "reached", "succeeded", "stolen": ["api_token:bob"], "canary_ids", "actor", "status_code", "actual" } ],
  "ledger": [ { "step_id", "actor", "request", "status_code", "record_id", "record_owner", "exposed_fields", "exposure_status", "canary_match", "detection", "authorized": false } ],
  "stolen": ["api_token:alice", …], "reached_final": true, "steps_reached": 3, "final_records": ["DOC-202","DOC-303"], "chain_succeeded": true }
```
On the unpatched fixture the chain reaches step 3 and the ledger shows other users' records; with the SQLi fix applied it stops at step 1 with an empty ledger.
