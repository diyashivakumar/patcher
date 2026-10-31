# PatchProof — Final QA & Security Validation Report

PARALLAX 2026 · QA pass dated 2026-10-30/31 · branch `main` @ `1832936` plus uncommitted work (nothing committed or pushed)

**Recommendation: READY WITH KNOWN LIMITATIONS** (section 9)

---

## 1. Executive summary

The central question was: *can PatchProof claim that a vulnerable application has been securely patched?*

**Yes, it could. I proved it twice, and both cases are now fixed.**

| ID | Severity | False VERIFIED reproduced | Root cause | Status |
|---|---|---|---|---|
| QA-1 | **Critical** | A SQLi "fix" that kept the injectable f-string but **filtered marked rows from the output** (and fell back to a safe query on errors) was VERIFIED, yet `' UNION SELECT 1, username \|\| ':' \|\| role FROM users --` still dumped every user. | Every SQLi oracle detected *specific marked data* (canaries, private titles, tokens), so hiding that data looked like a fix. | **Fixed:** execution probes |
| QA-2 | **Critical** | An IDOR "fix" that still served other students' canary records with **base64-encoded fields** was VERIFIED. | Forensics only recognised visible markers; the PrivilegeMap tests only probe documents 1 and 2. | **Fixed:** record-identity oracle |

After the fixes, **the same two adversarial apps come out FAILED**, with the exact cause stated ("still EXECUTED the injected SQL" and "still returned DOC-202"). All genuine fixes stay VERIFIED. Both apps are now permanent reference fixtures with regression tests.

The authoritative verdict logic (`testing/verdict.py`) itself behaved correctly in all 13 edge cases I threw at it. The flaws were in the *evidence* feeding it.

I also found and fixed:
- a network-guard gap (QA-3);
- two validation gaps (QA-4, QA-5);
- a backend defence-in-depth gap (QA-6);
- a saved-bypass oracle loss (QA-8);
- a misleading dashboard metric (QA-9);
- UI wording (QA-10).

---

## 2. Test execution results

Final run, after all fixes. Windows 11, Python 3.11, Node 24.

| Suite | Exact command | Result | Skipped | Warnings | Time |
|---|---|---|---|---|---|
| Backend (in-memory SQLite with FK enforcement; runs the real runner subprocess) | `cd backend; .\venv\Scripts\python -m pytest -q -rs` | **60 passed, 0 failed** | 0 | 1 (Starlette/anyio deprecation, third-party) | 18.6 s |
| Testing framework + fixtures | `python -m pytest testing/tests -q -rs` (repo root, `.venv-testing`) | **61 passed, 0 failed** | 0 | 0 | 5.3 s |
| Frontend type check | `cd frontend; npx tsc -b` | pass | – | – | ~8 s |
| Frontend production build | `cd frontend; npm run build` | pass (JS ≈ 297 kB / 86 kB gzip) | – | – | ~13 s |

Baseline before QA (same commands): backend 53 passed; testing 31 passed; type check and build passed.
**Net additions: +7 backend tests and +30 testing tests.** No existing assertion was weakened or removed.

Fixture tests live in `testing/tests/` (they execute the fixture and its variants). Integration tests are the backend API flow tests, which run the real runner subprocess, plus the live Neon checks in section 4.

---

## 3. Security validation

Unless marked *(Neon)* or *(browser)*, results come from automated tests executing the real fixture.

### SQL injection
| Check | Result |
|---|---|
| Baseline reproduces on the vulnerable fixture | ✅ the tautology and UNION exploits succeed; forensics shows DOC-101/202/303 **titles** (tautology) and **bodies** (UNION) |
| Normal searches work on the vulnerable fixture | ✅ `Algebra`, empty search. ❌ `O'Brien` crashes with HTTP 500, which is pre-existing, intended fixture behaviour |
| Naive blocklist: variants bypass | ✅ the original payload is blocked; **7 bypasses**: whitespace, case, comment, position, UNION, plus both new probes. **FAILED** |
| Naive blocklist: forensics | ✅ records still exposed: DOC-101/202/303 (title and body) |
| Parameterised query | ✅ all 9 valid variants blocked (both probes `blocked` with `probe_hit=true` on the original); 1 invalid (double-encoded) not counted; legitimate searches work; 0 records exposed; **VERIFIED** *(also Neon, run 4029f41d)* |
| Saved bypasses replayed | ✅ 5 saved cases replayed and blocked; no duplicates *(Neon, earlier session; automated now)* |
| **Adversarial output-filter patch** | ❌→✅ **was VERIFIED (QA-1); now FAILED** |

### IDOR / broken access control
| Combination | Original | Deny-all | Ownership check |
|---|---|---|---|
| A → own (DOC-101, doc 1) | allowed | ❌ denied (regression) | ✅ allowed |
| A → B, B → A, C → B, A → C | exposed | blocked | ✅ blocked |
| Assigned teacher → A | allowed | ❌ denied | ✅ allowed |
| Unassigned or other teacher → B / A | exposed | blocked | ✅ blocked |
| Anonymous → private | exposed | blocked | ✅ blocked |
| Leading-zero id `/documents/0202` | exposed (valid variant) | blocked | ✅ blocked |
| **Verdict** | – | **FAILED** (9 blocked, 4 legitimate broken; the evidence lists the lost access to DOC-101/202/303) | **VERIFIED** *(also Neon, run a9a17aba)* |
| **Adversarial encoded-field patch** | – | – | ❌→✅ **was VERIFIED (QA-2); now FAILED** |

### Exploit Variant Gauntlet
| Requirement | Result |
|---|---|
| Every variant runs on the original, then the patched app | ✅ (`before`/`after` per case) |
| Not reproduced on original → `invalid`, never counted as blocked | ✅ (double-URL-encoded; unit test with 9 invalid variants) |
| Blocked / bypass / inconclusive classification | ✅ (verdict edge tests; adversarial runs) |
| Legitimate requests treated as regressions, not attacks | ✅ (`works` / `regression_failed`) |
| Saved bypasses replayed; no duplicates | ✅ (deduplicated by fingerprint and linked to the built-in variant) |
| Saved cases cannot bypass the safety allowlist | ✅ after QA-4 (raw_query) and the new oracle allowlist. Rejected: `;`, DROP/UPDATE/…, POST, external URLs, unknown actors, extra params, unknown oracle types |
| Ways to report a patch as secure incorrectly | **QA-1 and QA-2 found and fixed.** Remaining theoretical case: O-2 |

### Data Exposure Forensics
| Requirement | Result |
|---|---|
| Marker → correct record, field and actor | ✅ (unit tests; ledger rows on Neon show actor, record, owner, fields, markers, evidence ref) |
| 403 with marker counts as exposure; 200 without does not | ✅ (unit tests) |
| One field's marker ≠ every field | ✅ (`partial_field_exposure`; search exposes `title` only) |
| Multiple records | ✅ (`multiple_records_exposed`) |
| No exposure without evidence | ✅. The identity oracle requires the record's own `id` in a 2xx JSON body for an unauthorised actor; authorised and denied requests are not flagged (test) |
| No bodies or secrets in Gauntlet/Forensics evidence or reports | ✅ (tests assert no body text and no `tok-` in Gauntlet/Forensics output or the HTML report). See O-3 for the *classic* test evidence |

### Verdict engine (`testing/verdict.py`, authoritative)
| Scenario | Expected (spec) | Actual |
|---|---|---|
| All valid attacks blocked, legit OK | VERIFIED | ✅ VERIFIED |
| Any bypass | FAILED | ✅ FAILED |
| Attacks blocked, legit broken | FAILED | ✅ FAILED |
| Unreliable evidence (runner error, timeout, malformed output) | INCONCLUSIVE | ⚠️ **FAILED**. No INCONCLUSIVE verdict exists (see O-1). Never VERIFIED |
| Invalid variant | not counted | ✅ |
| Patched app errors on a variant | INCONCLUSIVE | ⚠️ **PARTIALLY_VERIFIED** (amber), or FAILED when the classic security tests also see the 5xx. Never VERIFIED |
| Empty security or regression test set | not passed | ✅ FAILED |
| Partial failure (one test errored) | not passed | ✅ FAILED |
| Counts consistent runner → backend → frontend | consistent | ✅ The backend now **rejects** output whose counts don't match its cases, or that says VERIFIED with bypasses (QA-6). The report JSON matches the stored run (checked on Neon). The frontend only displays values |

---

## 4. Integration validation

### Database / Neon (live, read-mostly)
- Alembic history is linear: `0001_initial → 0002_gauntlet_forensics (head)`. Neon is at head.
- `compare_metadata` (models vs live Neon) reports **NONE**.
- Persistence: gauntlet, forensics and regression cases are stored and retrieved. **Two new runs were created** by re-verifying already-applied patches. No records were deleted, no destructive SQL was run, and `.env` was neither read nor printed.
- Older runs (5 pre-Gauntlet) return `gauntlet: null, forensics: null` with their tests intact (verified on run `1c8bb85c`).
- Error handling (live): unknown IDs give 404; a malformed UUID, empty body or unknown scenario gives 422 with the standard error format.
- Report consistency: report JSON verdict, gauntlet counts and forensics comparison equal the stored run (2 Neon runs).

### Security boundaries
| Boundary | Result |
|---|---|
| ZIP traversal (`../`, `..\`, `a\..\..\`, `C:\`, UNC `\\server\share`, `/etc/…`) | ✅ all rejected; nothing written outside storage *(this QA)* |
| Symlinks, ZIP bombs, oversize, non-ZIP, no `.py`, secret files | ✅ (existing tests) |
| Uploaded code never executed | ✅ Only `testing/harness.py` imports code, and only from fixture copies; the engine refuses non-fixture projects *(code review + API test)* |
| Runner subprocess environment | ✅ It sees only `COMSPEC, PATH, PATHEXT, PYTHONDONTWRITEBYTECODE, PYTHONNOUSERSITE, SYSTEMROOT, TEMP, TMP, TMPDIR, WINDIR`. **No `DATABASE_URL`**, no keys or tokens (probed with a real subprocess while the parent had `DATABASE_URL` loaded) |
| Subprocess timeout | ✅ A hanging app gives `RunnerError("…time limit")`, so the run fails (test with a 3 s limit) |
| Network | ⚠️→✅ **QA-3:** `connect_ex` and UDP `sendto` reached the network; now blocked, along with `sendmsg` and DNS |
| CPU and memory limits | ⚠️ **Not on Windows.** POSIX only (`RLIMIT_CPU`, `RLIMIT_AS`); Windows relies on the timeout alone. Not claimed |
| Patch approval | ✅ `approved: true` required; ⚠️→✅ **QA-5:** whitespace-only approver is now rejected and names are trimmed |
| Backup and rollback | ✅ (existing tests: per-patch rollback, restore matches the original) |

### Frontend / end-to-end
Browser tests, real backend plus Neon, in Chrome:

| Area | This QA pass | Earlier sessions (same build lineage) |
|---|---|---|
| Dashboard stats match API | ✅ (verdict counts 6✓/3✗ match DB; **open findings 0 after QA-9**) | ✅ |
| Gauntlet page: probes, labels, expand, regression cases | ✅ (new probe rows, "Injected SQL executed", no console errors) | ✅ bypass panel, matrix, stale-race fix |
| Timeline matches backend | ✅ (run 4029f41d: Attack Replay and Final Verdict Passed = VERIFIED) | ✅ SQLi, deny-all, ownership |
| Forensics page, inspector, ledger | – | ✅ |
| Lab approve, apply, verify; reports; upload errors; backend-down banner; AI explanation | – | ✅ |
| FAILED vs PARTIALLY_VERIFIED distinguishable | Code review: FAILED red ✗, PARTIAL amber ⚠ | not rendered live (no PARTIALLY_VERIFIED run exists in Neon) |
| Console errors | none | none |
| Mock data presented as real | No. Mock mode is off by default and bannered when on | ✅ |

**Not browser-tested:** report download buttons (they save files locally); a PARTIALLY_VERIFIED run; ZIP upload in this pass (done in an earlier session).

---

## 5. Issues discovered

| ID | Sev | Component | Reproduction | Impact |
|---|---|---|---|---|
| QA-1 | Critical | `testing/gauntlet.py` oracles | Run `run_compare(vulnerable_app, fixtures/variants/output_filter, "sqli")` before the fix → VERIFIED; send `q=' UNION SELECT 1, username FROM users --` → user list | False VERIFIED for a still-injectable app |
| QA-2 | Critical | `testing/gauntlet.py` oracles | Run `run_compare(vulnerable_app, fixtures/variants/idor_encoded, "idor")` before the fix → VERIFIED; alice still gets DOC-202 (base64) | False VERIFIED for a still-broken access check |
| QA-3 | Medium | `testing/harness.py` network guard | `socket.socket().connect_ex(("192.0.2.1", 9))` and UDP `sendto` returned normally under the guard | Fixture code could reach the network; the documented isolation was overstated |
| QA-4 | Low | `validate_variant` | `raw_query: "q=x&admin=1"` accepted | Allowlist weaker than documented |
| QA-5 | Low | `PatchApply` schema | `approved_by: "   "` accepted | Blank approver in the audit log |
| QA-6 | Low (defence in depth) | `adapter._validate` | A hand-edited runner output with VERIFIED plus bypass, or mismatched counts, was accepted | The backend would store a contradictory verdict if the runner misbehaved |
| QA-7 | – (verified) | adapter timeout | A hanging app gives a runner error | Behaviour correct; test added |
| QA-8 | Low | backend preserve, `RegressionCaseOut` | Saved bypass stored `check=None`, and the API didn't expose `check` | A replayed probe-based saved case could not re-detect its bypass |
| QA-9 | Medium (demo) | `/dashboard/summary`, Dashboard | After all fixes were VERIFIED, the dashboard still showed "Open findings 3" | Misleading claim to judges |
| QA-10 | Low (UI) | Gauntlet labels | A probe's "Expected" read "No protected canary data returned"; new outcomes rendered as raw identifiers | Confusing evidence |

---

## 6. Fixes implemented

| ID | Fix | Files | Regression tests |
|---|---|---|---|
| QA-1 | SQLi execution probes `sqli.gv.union_probe` (UNION constant marker) and `sqli.gv.boolean_probe` (rows for a literal that matches nothing); outcome `injection_executed`; bypass reason names the cause | `testing/gauntlet.py` | `testing/tests/test_qa_regressions.py::test_output_filter_sqli_patch_is_rejected`, `test_probes_are_valid_on_original_and_blocked_by_real_fix`; new fixture `fixtures/variants/output_filter/app.py` |
| QA-2 | Record-identity oracle: unauthorised 2xx JSON containing the requested canary record's `id` counts as exposure (`detection: record_identity`) | `testing/gauntlet.py` | `test_encoded_idor_patch_is_rejected_with_identity_evidence`, `test_identity_oracle_does_not_flag_authorised_or_denied_requests`; new fixture `fixtures/variants/idor_encoded/app.py` |
| QA-3 | Guard `connect`, `connect_ex`, `sendto`, `sendmsg`, `create_connection`, `getaddrinfo`, `gethostbyname(_ex)` | `testing/harness.py` | `test_network_guard_covers_all_ip_entry_points` (4 cases) |
| QA-4 | `raw_query` must contain exactly one `q`; attack and legit oracles allowlisted and validated | `testing/gauntlet.py` | `test_raw_query_must_be_exactly_one_q`, `test_single_q_raw_query_still_allowed`, `test_attack_oracles_are_allowlisted` |
| QA-5 | Trim the approver name; reject blank | `backend/app/schemas/patch.py` | `backend/tests/test_qa_regressions.py::test_whitespace_only_approver_is_rejected` |
| QA-6 | Adapter rejects mismatched gauntlet counts, and VERIFIED with bypasses or broken legitimate variants (→ runner error → FAILED) | `backend/app/verification/adapter.py` | `test_adapter_accepts_consistent_runner_output`, `test_adapter_rejects_verified_with_bypass`, `test_adapter_rejects_counts_that_do_not_match_cases` |
| QA-7 | — (verified) | — | `test_hanging_app_hits_the_timeout` |
| QA-8 | Persist `check` with saved bypasses; expose `check` in `GET /regression-cases`; carry `check` in Gauntlet cases | `backend/app/verification/engine.py`, `backend/app/schemas/verification.py`, `testing/gauntlet.py` | `test_preserved_bypass_keeps_probe_oracle`, `test_saved_case_keeps_its_probe_oracle` |
| QA-9 | `open_findings` / `open_findings_by_severity` = latest-scan findings without a VERIFIED patch; Dashboard uses them | `backend/app/routes/health.py`, `frontend/src/pages/Dashboard.tsx`, `frontend/src/types/api.ts` | `test_dashboard_open_findings_exclude_verified_patches` |
| QA-10 | Probe-specific "Expected" and "blocked" wording; labels for `injection_executed` and `record_returned_markers_not_visible`; ledger shows the detection method | `testing/gauntlet.py`, `frontend/src/components/GauntletParts.tsx`, `frontend/src/pages/{Gauntlet,Forensics}.tsx`, `frontend/src/types/api.ts` | covered by `test_probes_are_valid…` (reason text); browser-checked |
| — | Verdict edge-case suite (no bug found) | — | `testing/tests/test_qa_verdict_edges.py` (13 tests; named to avoid clashing with Dipto's `test_verdict.py`) |

Documentation updated: `docs/testing_contract.md` (oracles, allowlist, network guard), `docs/api_contract.md` (`open_findings`, `check`), `docs/threat_model.md` (network guard).

---

## 7. Remaining limitations

| ID | Limitation | Why not fixed |
|---|---|---|
| O-1 | **No INCONCLUSIVE verdict.** Unreliable evidence gives FAILED (runner error or timeout) or PARTIALLY_VERIFIED (inconclusive variant). Neither is ever VERIFIED. | Adding a verdict changes the runner schema, the DB values and the UI. Needs a joint decision (Diya and Dipto). |
| O-2 | **Test-aware patches.** The variant set and synthetic IDs are fixed, so a patch written to special-case these exact IDs or inputs could still pass. | Mitigated: patches come only from PatchProof's deterministic generator (4 strategies) and need human approval; there is no API for submitting arbitrary patches. A future idea is to randomise synthetic IDs per run. |
| O-3 | **Classic test evidence** (`evidence.response.body_excerpt`, ≤ 600 chars) stores synthetic response text, including the fabricated `tok-…-SYNTHETIC` tokens leaked by the UNION test, in Neon and the UI. | It's fabricated data and is the proof of the leak. Redaction is Dipto's call. |
| O-4 | **Neon latency:** 1–3.5 s per API call, so pages take about 5–15 s to load. | Infrastructure. Warm up Neon before the demo and keep the backend running. |
| O-5 | **Windows: no CPU or memory limits** for the runner, only the timeout. The network guard is in-process, not an OS sandbox. | Proper sandboxing (container, job object) is out of scope. Only trusted fixture code runs. |
| O-6 | *Analysis only, not reproduced:* stacking a second patch via a newer scan's finding while an older patch is applied could make the older patch's rollback hit a `rollback_conflict` (409, with backup kept). | No data loss; the conflict is reported. Low priority. |
| O-7 | The 5 regression cases saved on Neon before QA-8 have `check: null`. | They are linked to built-in variants, which carry their own oracles, so replay is unaffected. |
| O-8 | If a fixture produced zero valid attack variants, the Gauntlet would add no evidence; the verdict would rest on the classic tests. | Not observed (9 valid SQLi, 9 valid IDOR). |
| O-9 | Changes to `testing/` and `fixtures/` (feature work and this QA) still need **Dipto's review**. `feature/testing-dipto` is unmerged. | Process, not code. |
| — | Not browser-tested: report downloads, a PARTIALLY_VERIFIED run, ZIP upload in this pass. The Ollama fallback was covered by unit tests here and browser-tested in an earlier session. | — |

---

## 8. Hackathon demonstration readiness

| Demonstration | Works? | Evidence |
|---|---|---|
| SQLi exploit reproduction | ✅ | automated + Neon |
| Naive blocklist → bypasses found → FAILED | ✅ (now 7 bypasses incl. probes) | automated; Neon earlier session |
| Parameterised query → VERIFIED, saved bypasses replayed | ✅ | automated + Neon run 4029f41d |
| IDOR reproduction + PrivilegeMap | ✅ | automated + Neon |
| Deny-all → FAILED (legitimate access broken) | ✅ | automated; Neon earlier session |
| Ownership check → VERIFIED | ✅ | automated + Neon run a9a17aba |
| Data Exposure Forensics (ledger, inspector, before/after) | ✅ | automated; browser earlier session |
| Live Attack Timeline | ✅ | browser |
| Reports (JSON/HTML) | ✅ (download buttons not clicked) | automated + Neon |
| Dashboard reflects reality | ✅ after QA-9 | browser + Neon |
| New: "PatchProof catches cheating fixes" (output filter, encoded fields) | ✅ via runner and tests | automated (these patches can't be produced through the UI, by design) |

---

## 9. Final recommendation

### **READY WITH KNOWN LIMITATIONS**

Every critical demonstration works against the real Neon-backed system. The two reproducible ways PatchProof could falsely certify a vulnerable app are fixed and pinned by regression tests. Every safety boundary I attacked held after fixes. The limitations in section 7 are documented and none of them produces a false VERIFIED through the product's actual workflow. Before the demo: warm up Neon (O-4), and have Diya and Dipto jointly review O-1, O-3 and the `testing/`/`fixtures/` changes (O-9).
