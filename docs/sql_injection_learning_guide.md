# SQL injection: learning and implementing PatchProof

This repository already implements a local SQL injection demonstration, detection, repair, and verification workflow. Use the bundled synthetic fixtures for the exercises below.

## What to learn, in order

| Topic | What you should be able to explain or implement | Repository example |
|---|---|---|
| SQL foundations | Tables, SELECT, WHERE, AND/OR precedence, LIKE, UNION, comments, joins, and NULL | `fixtures/seed/student_portal.sql` |
| Python foundations | Functions, dictionaries, exceptions, context managers, modules, virtual environments | `testing/harness.py` |
| HTTP and Flask | Routes, query parameters, JSON responses, status codes, request/response flow | `fixtures/vulnerable_app/app.py` |
| SQLite access | Connections, cursors, execute, fetchall, transactions, bound parameters | Fixture `get_db()` and `/search` |
| Injection mechanics | How interpolated input becomes SQL syntax; boolean and UNION injection | `testing/scenarios/sqli.py` |
| Defensive queries | Separate SQL structure from values with driver parameters | `fixtures/variants/patched_reference/app.py` |
| Static analysis | Python AST, assignments, f-strings, concatenation, source-to-sink tracking, false positives and negatives | `backend/app/scanner/sqli.py` |
| Patch generation | Minimal changes, diffs, supported patterns, static validation, approval, backup and rollback | `backend/app/patching/` |
| Security testing | Reproduce a leak, replay the identical request after repair, assert response contents | `testing/scenarios/sqli.py` |
| Regression testing | Normal searches, empty searches, apostrophes, legitimate access | `testing/scenarios/sqli.py` |
| Evidence and verdicts | Why a blocked exploit alone does not prove a useful fix | `testing/verdict.py` |
| Full application integration | FastAPI, Pydantic, SQLAlchemy, migrations, React, TypeScript, API calls | `backend/app/`, `frontend/src/` |

For the SQL injection module, prioritize SQL, Python, Flask, parameter binding, and pytest. React and PostgreSQL administration are needed for the full dashboard, not for understanding the local exploit.

## Understand the exact bug

The fixture takes `q` from the URL and inserts it directly into SQL:

```python
term = request.args.get("q", "")
sql = f"SELECT id, title FROM documents WHERE is_public = 1 AND title LIKE '%{term}%'"
rows = get_db().execute(sql).fetchall()
```

With the local test input `' OR 1=1 --`, the query becomes:

```sql
SELECT id, title FROM documents
WHERE is_public = 1 AND title LIKE '%' OR 1=1 --%'
```

The quote ends the string, `OR 1=1` makes the condition true, and the comment removes the remaining SQL text. Because AND binds more tightly than OR, private rows can be returned too. The second existing test uses UNION to put synthetic user tokens into the search response. UNION requires compatible result columns; this fixture selects two columns.

## Implement the repair

```python
term = request.args.get("q", "")
sql = "SELECT id, title FROM documents WHERE is_public = 1 AND title LIKE ?"
rows = get_db().execute(sql, (f"%{term}%",)).fetchall()
```

SQLite receives fixed SQL plus a separate parameter tuple. The trailing comma makes a one-element tuple. The f-string in the parameter is safe here because its result is passed as data, rather than inserted into SQL text.

Learn these distinctions:

- Parameter markers are driver-specific; this SQLite example uses `?`.
- Bound values do not substitute table names, column names, or sort directions. Choose those from explicit allowlists when dynamic identifiers are necessary.
- Input validation complements parameterization; banning apostrophes or manually escaping quotes is not the general fix.
- LIKE still interprets `%` and `_` as wildcards inside bound values. Escape them separately if literal substring matching is required.
- Authorization remains necessary. A parameterized query can still expose another user's data through an IDOR bug.
- Error-based, boolean-blind, and time-based injection are further theory topics; this repository does not implement coverage of every SQL injection family.

## Run the SQL injection demonstration

Use PowerShell from the repository root. No Neon database or running web server is needed: the harness creates SQLite data and uses Flask's test client.

```powershell
# First-time setup, if dependencies have not already been installed:
python -m venv backend/.venv
./backend/.venv/Scripts/python.exe -m pip install -r backend/requirements.txt

# Observe the vulnerable baseline:
./backend/.venv/Scripts/python.exe -m testing.runner --scenario sqli --app-dir fixtures/vulnerable_app --phase baseline

# Compare vulnerable and correctly repaired fixtures; save all evidence:
./backend/.venv/Scripts/python.exe -m testing.runner --scenario sqli --original-dir fixtures/vulnerable_app --patched-dir fixtures/variants/patched_reference --output docs/sqli-proof.json

# Validate the testing framework:
./backend/.venv/Scripts/python.exe -m pytest testing/tests -q

# Validate the backend (run from its directory):
Set-Location backend
./.venv/Scripts/python.exe -m pytest -q
```

Expected comparison: both baseline security tests fail because the exploits work; both patched security tests pass; all three patched regression tests pass; verdict is VERIFIED. The baseline apostrophe regression also fails, illustrating a correctness bug fixed by parameterization. A runner exit code of zero means it produced a report; read the verdict and individual tests to determine security results.

## Start the full dashboard

1. Put your PostgreSQL connection string in `backend/.env` as `DATABASE_URL=postgresql://...`. Do not commit credentials. SQLite in the testing harness is separate from this application database.
2. From `backend`, run `./.venv/Scripts/python.exe -m alembic upgrade head`, then `./.venv/Scripts/python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000`.
3. In another terminal, enter `frontend`, run `npm.cmd install`, then `npm.cmd run dev`.
4. Open the URL printed by Vite. Create a fresh bundled demo project, scan, select SQL injection, reproduce the baseline, generate and review the patch, approve it, and verify.
5. For a UI-only preview without PostgreSQL, use `VITE_USE_MOCKS=true` in `frontend/.env`. Mock results are illustrative, not executed proof.

## Suggested hands-on sequence

1. Read the seed SQL and predict which documents a public search should return.
2. Trace `q` from the HTTP request to `execute()` and explain the vulnerable SQL by hand.
3. Run the baseline and inspect the recorded request and leaked synthetic response.
4. Compare the vulnerable search with the reference repair and explain parameter binding.
5. Run the before/after comparison. Explain every security and regression result.
6. Read the AST scanner and identify which string construction patterns it supports.
7. Follow a finding through patch generation, approval, verification, and reporting.

You understand the module when you can demonstrate the original flaw, explain why the patch removes SQL syntax control, and prove that ordinary search still works. Passing these specific tests is evidence for these cases, not a guarantee that every vulnerability has been found.
