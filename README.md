# PatchProof

### Find the Flaw. Prove the Fix.

PatchProof is an evidence-driven application security platform built for **PARALLAX 2026**. It scans code for security vulnerabilities, proposes a minimal defensive patch, and then **proves** whether the patch works. It does this by re-running the real attack against an isolated patched copy and checking that legitimate users can still do their jobs.

> **We do not just find vulnerabilities. We prove that the fix works.**

PatchProof is for learning and demonstration. It targets a **deliberately vulnerable practice app that ships with this repo**, uses **synthetic data only**, and never attacks systems outside your machine.

---

## Contents
- [A. Introduction](#a-introduction) · [B. Problem](#b-problem-statement) · [C. Features](#c-key-features) · [D. How it works](#d-how-the-complete-system-works) · [E. Architecture](#e-architecture)
- [F. Tech stack](#f-technology-stack) · [G. Repo structure](#g-repository-structure) · [H. Team](#h-team-division)
- [I. Requirements](#i-installation-requirements) · [J. Environment](#j-environment-configuration) · [K. Backend](#k-backend-setup-windows-powershell) · [L. Frontend](#l-frontend-setup) · [M. Testing](#m-testing-setup) · [N. API](#n-api-documentation) · [O. Ollama](#o-ollama-setup-optional)
- [P. Demo walkthrough](#p-demo-walkthrough) · [Q. Limitations](#q-security-limitations) · [R. Troubleshooting](#r-troubleshooting)

---

## A. Introduction

PatchProof takes a codebase and:
1. **finds** SQL injection and broken access control (IDOR) flaws, pointing at the exact file and lines;
2. **explains** what is wrong, why it matters and how severe it is;
3. **proposes** a small, reviewable patch, which a human must approve before it is applied;
4. **proves** the fix by replaying the original exploit before and after the patch, plus regression tests for legitimate behaviour;
5. **reports** the evidence in a verification report.

The key piece is the **Proof-of-Fix Engine**. A patch is never considered "verified" just because code changed.

## B. Problem statement

- **Scanners are noisy.** Static tools flag patterns, but a finding doesn't prove that anything is exploitable. Teams waste time triaging, or start ignoring the tool.
- **Automated fixes can break things.** An auto-generated "fix" might block the attack *and* block real users, or it might change code without closing the hole. Both are common.
- **"It compiles" is not proof.** Even re-scanning a patched file only shows that the pattern disappeared, not that the attack stopped working or that features still work.

PatchProof treats a fix as a hypothesis. It must (1) reproduce the original vulnerability, (2) show that the same exploit is blocked after patching, and (3) show that legitimate functionality still works. If any of these fails, the patch is rejected.

## C. Key features

| Feature | In plain English |
|---|---|
| **Source code scanner** | Reads Python files using Python's own parser (AST) rather than plain text search, so it understands which variable flows into which function call. |
| **SQL injection detection** | Flags database queries built by gluing user input into SQL text (f-strings, `+`, `%`, `.format`). Traces the input back to the HTTP request to judge severity. |
| **IDOR detection** | Flags web routes that load a record by an ID from the URL and return it without checking that the caller is allowed to see it. |
| **Vulnerability findings** | Each finding has the file, line range, highlighted code, a data-flow trace, explanation, impact, severity with rationale, confidence, CWE, remediation and detection method. |
| **Patch generation** | Builds a minimal patch deterministically (no AI): parameterised queries for SQLi, and a call to the app's existing authorisation check for IDOR. |
| **Patch review** | Unified diff, original and proposed code side by side, rationale, and static checks. Nothing changes on disk until a named person approves. Every apply backs up the file. |
| **Rollback** | Reverses exactly one patch and leaves other applied patches in place. |
| **PrivilegeMap** | A table of who should be able to read what (e.g. *Alice → Bob's document = DENY*, *teacher → assigned student's document = ALLOW*). Every row becomes an executable test. |
| **Attack Replay Lab** | A guided 5-step page: run the real exploit, locate the code, review the patch, approve, then replay the same attack and see the before/after evidence. |
| **Proof-of-Fix Engine** | Runs the exploit and regression tests against the original and the patched copy in isolation, and computes the verdict `VERIFIED`, `PARTIALLY_VERIFIED` or `FAILED` from the actual results. |
| **Over-restrictive patch rejection** | A deliberately bad "deny everyone" patch blocks the attack but breaks legitimate users. PatchProof rejects it, even though a static re-scan considers it fine. |
| **Regression testing** | Checks normal behaviour: searches still work (including names with apostrophes), owners can read their documents, teachers can read their students' documents. |
| **Security reports** | JSON and printable HTML verification reports with all evidence and known limitations. |
| **Exploit Variant Gauntlet** | *One exploit is not enough.* Every Proof-of-Fix also replays validated variations of the attack: case, spacing, SQL comments, URL encoding, injection position and UNION for SQLi; many actor/record combinations for IDOR. Each runs on both the original and the patched app. A variant that doesn't reproduce on the original is marked **invalid** and never counted as a block. A variant that still works after the patch is a **bypass**: the patch is rejected and the case is saved as a regression test for every future run. |
| **Data Exposure Forensics** | *Show exactly what got exposed.* Synthetic canary records (DOC-101/202/303) carry a marker in every field. PatchProof inspects each actual response for those markers and builds an **exposure ledger**: which actor saw which record and which fields, before and after the patch. Exposure is never inferred from the HTTP status alone. |
| **Windows Port Inspector** | A read-only view of which TCP/UDP services are listening locally and how widely they are exposed (localhost vs. a specific interface vs. all interfaces), with a transparent risk heuristic that flags sensitive ports (SMB, RDP, databases, etc.) open on all interfaces. It never terminates a process or touches the firewall. |
| **Live Website Security Check** | A deliberately non-invasive review of a public website's HTTPS/TLS, security headers, cookie flags and configuration using only ordinary GET/HEAD requests — no scanning, brute forcing or exploitation. Strict SSRF protections reject private/loopback/link-local/metadata targets, pin the connection to a validated IP (anti-DNS-rebinding) and re-validate every redirect. Cookie *values* and auth tokens are never collected. |
| **Optional Ollama assistance** | A local AI can write a friendlier explanation of a finding. It is advisory only and the app works fully without it. |

## D. How the complete system works

1. **Create a project.** Pick the bundled practice app (or upload a ZIP). PatchProof stores two copies: `original/`, which is never touched, and `source/`, the working copy that patches go into.
2. **Scan.** Every `.py` file is parsed into a syntax tree. For SQLi, the scanner finds `.execute(...)` calls and checks how the SQL string was built. For IDOR, it finds routes with a `<doc_id>`-style parameter that is used in a lookup without any ownership or permission check. Findings are stored in Neon with exact line numbers.
3. **Reproduce (baseline).** PatchProof copies the original code to a temp folder and runs Dipto's test runner. The runner seeds a fresh, synthetic SQLite database, sends real HTTP requests through Flask's test client (for example `GET /search?q=' OR 1=1 --`), and records the responses as evidence.
4. **Patch.** The generator rewrites only the affected lines. For example `f"... LIKE '%{term}%'"` becomes `"... LIKE ?"` with the parameter `(f"%{term}%",)`. It shows a diff and statically re-checks the result.
5. **Approve and apply.** A person enters their name and confirms. PatchProof backs up the file, checks that the original lines are still exactly there, and writes the change.
6. **Proof-of-Fix.** The original and patched copies are put in two temp folders. The runner runs the **same** exploits and the regression tests against both, in a subprocess with a timeout, no secrets and no network.
7. **Verdict** (deterministic, from executed tests only):
   - **VERIFIED**: the exploit worked before the patch, *every* security test passes after it, and *every* regression test passes after it.
   - **PARTIALLY VERIFIED**: everything passes afterwards, but the original exploit couldn't be reproduced, so the fix can't be proven.
   - **FAILED**: any security or regression test fails afterwards, the app fails to load, tests are missing, or the run errors.
   A VERIFIED patch is accepted. A FAILED patch is marked REJECTED and can be rolled back.
8. **Report.** Everything is stored in Neon and can be viewed as a JSON or HTML report.

## E. Architecture

```mermaid
flowchart TB
  UI["React + TypeScript frontend"] -->|"HTTP /api"| API["FastAPI backend"]
  API --> NEON[("Neon PostgreSQL<br/>PatchProof's own records")]
  API --> SCAN["Source analysis engine<br/>(Python AST)"]
  API --> PATCH["Patch generation engine<br/>(+ apply / rollback)"]
  API --> VER["Verification adapter"]
  API -.optional.-> OLL["Ollama (local AI)"]
  VER -->|"subprocess: python -m testing.runner"| RUN["Dipto's independent testing framework"]
  RUN --> FIX["Isolated copies of the vulnerable Flask app"]
  FIX --> SQLITE[("Throwaway SQLite with synthetic data<br/>(separate from Neon)")]
```

**Two databases, never confused.** Neon PostgreSQL stores PatchProof's projects, scans, findings, patches, verification runs and audit log. The practice app's SQLite database is synthetic, created fresh in a temp folder for each test phase, and deleted afterwards.

More detail: [docs/architecture.md](docs/architecture.md) · [docs/threat_model.md](docs/threat_model.md)

## F. Technology stack

| Technology | Used for | Why |
|---|---|---|
| React 18 + TypeScript + Vite | Frontend | Fast dev server, type safety against the API contract |
| Tailwind CSS 3 + Lucide React | Styling and icons | Consistent dark dashboard without a component framework |
| Python 3.11+ / FastAPI / Pydantic | Backend API | Typed request/response models and automatic Swagger docs |
| SQLAlchemy 2 + Alembic | ORM + migrations | Safe bound-parameter queries; versioned schema changes |
| psycopg 3 | PostgreSQL driver | Works with Neon's TLS connection strings |
| Neon PostgreSQL | Main database | Managed Postgres; JSONB for evidence |
| Python `ast` | Static analysis | Understands code structure, not just text |
| Flask + SQLite | Vulnerable practice app | Small, readable target |
| pytest | Test suites | Backend and testing framework tests |
| Ollama (optional) | Local AI explanations | No paid APIs; nothing leaves your machine |

## G. Repository structure

```
.
├── README.md                  ← you are here
├── .env.example               ← copy to .env (Diya)
├── docs/                      ← architecture, contracts, team division, threat model
├── backend/                   ← Diya
│   ├── app/
│   │   ├── main.py            FastAPI app, CORS, routers
│   │   ├── config.py          settings from environment
│   │   ├── database.py        Neon engine + sessions
│   │   ├── models/            SQLAlchemy tables (7)
│   │   ├── schemas/           Pydantic request/response models (= API contract)
│   │   ├── routes/            /api endpoints
│   │   ├── scanner/           engine.py, sqli.py, idor.py
│   │   ├── patching/          generator.py (patch building), applier.py (apply/rollback/backup)
│   │   ├── verification/      adapter.py (runs testing.runner), engine.py (Proof-of-Fix orchestration)
│   │   ├── ai/                ollama_service.py (optional)
│   │   ├── reports/           JSON + HTML verification reports
│   │   └── services/storage.py  project files + safe ZIP extraction
│   ├── alembic/               migrations (0001_initial_schema)
│   ├── tests/                 backend tests
│   └── storage/               runtime project files (git-ignored)
├── frontend/                  ← Chinmayee
│   └── src/ pages/ components/ services/ hooks/ types/ layouts/
├── testing/                   ← Dipto
│   ├── runner.py              CLI: python -m testing.runner
│   ├── harness.py             loads app copies, seeds DB, blocks network
│   ├── privilege_map.py       PrivilegeMap (expected access rules)
│   ├── scenarios/             sqli.py, idor.py (executable tests)
│   ├── verdict.py             Proof-of-Fix verdict rules
│   └── tests/                 tests for the framework itself
└── fixtures/                  ← Dipto
    ├── vulnerable_app/app.py  deliberately vulnerable Flask app (SQLi + IDOR)
    ├── seed/student_portal.sql  synthetic users and documents
    └── variants/              patched_reference/ (correct) and over_restrictive/ (deny-all)
```

## H. Team division

| Member | Role | Owns | Must not edit |
|---|---|---|---|
| **Diya** | Backend & security engine lead | `backend/`, `docs/api_contract.md`, `.env.example` | `frontend/`, `testing/`, `fixtures/` |
| **Chinmayee** | Frontend lead | `frontend/`, `docs/frontend_integration.md` | backend Python, models, migrations, `testing/`, `fixtures/` |
| **Dipto** | Security testing & verification lead | `testing/`, `fixtures/`, `docs/testing_contract.md` | `backend/`, Neon schema, `frontend/` |

The three pieces meet only at two documented interfaces: the HTTP API ([docs/api_contract.md](docs/api_contract.md)) and the test runner's CLI and JSON output ([docs/testing_contract.md](docs/testing_contract.md)). Chinmayee can work without the backend using mock mode. Dipto's suite runs without the backend. Full rules and Git workflow: [docs/team_division.md](docs/team_division.md).

## I. Installation requirements

- **Python 3.11 or 3.12** (3.11 is tested; `py -0` lists installed versions on Windows)
- **Node.js 20+** and **npm** (tested with Node 24, npm 11)
- **Git**
- A **Neon** account and project (free tier is fine): <https://neon.tech>
- **Ollama** (optional): <https://ollama.com>

## J. Environment configuration

Copy the template to the **repository root** and fill it in:

```powershell
Copy-Item .env.example .env
```

```ini
DATABASE_URL=postgresql://USER:PASSWORD@ep-xxxx.region.aws.neon.tech/neondb?sslmode=require
OLLAMA_BASE_URL=http://localhost:11434
OLLAMA_MODEL=
FRONTEND_ORIGIN=http://localhost:5173
```

Get `DATABASE_URL` from the Neon console under **Connection Details**. PatchProof requires PostgreSQL and adds `sslmode=require` for Neon hosts automatically. **Never commit `.env`.**

## K. Backend setup (Windows PowerShell)

```powershell
cd backend
py -3.11 -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt        # also installs Flask + pytest for the test runner
alembic upgrade head                   # creates the 7 tables in Neon (safe to re-run; never drops data)
uvicorn app.main:app --reload --port 8000
```

- API: <http://localhost:8000/api/health> should return `"database": "ok"`.
- Swagger docs: <http://localhost:8000/docs>
- Preview the migration SQL without connecting: `alembic upgrade head --sql`
- Future schema changes: edit the models, then run `alembic revision --autogenerate -m "describe change"`, review the file, and run `alembic upgrade head`.

If `Activate.ps1` is blocked, run `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` once, or call `.\venv\Scripts\python -m uvicorn ...` directly.

## L. Frontend setup

```powershell
cd frontend
npm install
Copy-Item .env.example .env
npm run dev
```

Open <http://localhost:5173>. To build the UI without the backend, set `VITE_USE_MOCKS=true` in `frontend/.env`. A **MOCK DATA** banner then appears on every page. Details: [docs/frontend_integration.md](docs/frontend_integration.md).

## M. Testing setup

```powershell
# Dipto's testing framework (from the repo root, any venv with testing/requirements.txt installed)
python -m pytest testing/tests -q

# Run the runner directly
python -m testing.runner --scenario sqli --app-dir fixtures/vulnerable_app --phase baseline
python -m testing.runner --scenario idor --original-dir fixtures/vulnerable_app --patched-dir fixtures/variants/patched_reference
python -m testing.runner --scenario idor --original-dir fixtures/vulnerable_app --patched-dir fixtures/variants/over_restrictive

# Backend tests (use an in-memory DB, no Neon needed; they run the real runner as a subprocess)
cd backend; .\venv\Scripts\python -m pytest -q

# Frontend type check + build
cd frontend; npm run build
```

The runner prints JSON with `phases.before_patch` and `phases.after_patch`. Each has `security_tests` and `regression_tests` with counts and per-test `expected`, `actual`, `status` and `evidence` (the request sent and the response received), plus a `verdict` with `status` and human-readable `reasons`. The full schema is in [docs/testing_contract.md](docs/testing_contract.md).

## N. API documentation

All endpoints are under `/api`. Interactive docs are at **<http://localhost:8000/docs>**. The full contract with examples is in [docs/api_contract.md](docs/api_contract.md).

| Area | Endpoints |
|---|---|
| Health | `GET /health`, `GET /health/ollama`, `GET /dashboard/summary` |
| Projects | `GET /fixtures`, `POST /projects`, `POST /projects/upload`, `GET /projects`, `GET /projects/{id}` |
| Port Inspector | `GET /host/ports` (Windows only; returns `supported:false` elsewhere) |
| Website check | `POST /site-checks`, `GET /site-checks`, `GET /site-checks/{check_id}` |
| Scans | `POST /scans`, `GET /scans/{id}`, `GET /scans/{id}/findings` |
| Findings | `GET /findings/{id}`, `POST /findings/{id}/ai-explanation` |
| Patches | `POST /patches/generate`, `GET /patches/{id}`, `POST /patches/{id}/apply`, `POST /patches/{id}/rollback` |
| Verification | `POST /verification/run`, `GET /verification`, `GET /verification/{run_id}` |
| Reports | `GET /reports`, `GET /reports/{report_id}?format=json|html` |

## O. Ollama setup (optional)

**Team configuration:** Ollama 0.40.13 runs **locally** (no cloud, no API key) with the model **`gemma4:e2b`** (4.6 GB on disk). The reference machine is Windows, an Intel Core Ultra 9 285H, an Intel Arc 140T integrated GPU and 31.4 GB RAM, with no NVIDIA or AMD GPU.

### Setup
1. Install Ollama: <https://ollama.com/download>, or in PowerShell run `irm https://ollama.com/install.ps1 | iex`. It runs a local service on port 11434.
2. Pull the model: `ollama pull gemma4:e2b`
3. Check it's there: `ollama list`, or open <http://localhost:11434/api/tags>
4. In the root `.env`, set `OLLAMA_BASE_URL=http://localhost:11434` and `OLLAMA_MODEL=gemma4:e2b`, then restart the backend.
5. Verify: `GET http://localhost:8000/api/health/ollama` should return `"model_installed": true` and `"message": "Ollama is ready."`

**To change the model:** run `ollama pull <name>`, set `OLLAMA_MODEL=<name>` in `.env` (it must match `ollama list`; `name` also matches `name:latest`), and restart the backend. Smaller models answer faster on this hardware. Larger ones will be noticeably slower without a dedicated GPU.

### What was actually tested (2026-10-30, reference machine above)
| Check | Result |
|---|---|
| Raw `/api/generate`, short prompt, thinking **on** (the model default) | ~9.6–10.1 s; most of the ~300 generated tokens were hidden reasoning |
| Same prompt, thinking **off** (`"think": false`) | **1.8 s**, same quality of answer |
| PatchProof SQLi explanation (real API → Ollama) | **11.4 s**, ~1,050 chars. Covers what is wrong, the impact and parameterised queries; no claim that anything is fixed or verified |
| PatchProof IDOR explanation | **12.6 s**, ~1,050 chars. Covers the IDOR, the impact, and calling `can_view_document` / returning 403 server-side |
| Backend responsiveness during inference | `/api/health` answered in ~210–260 ms while an explanation was being generated |
| Frontend | Spinner while waiting; advisory banner; answer shown in its own "AI explanation (optional)" card next to the scanner's deterministic explanation; a missing-model error is shown verbatim with a **Try again** button |

PatchProof sends `"think": false` because it only displays the final answer. If a model rejects that option, the request is retried without it. The backend waits up to `OLLAMA_TIMEOUT_SECONDS` (default 60 s). Generation speed is about 40 tokens/s on this machine.

### What the AI is (and is not) allowed to do
- It writes **advisory explanations only**, shown with a label saying so and capped at 4,000 characters.
- It is **never** used to detect vulnerabilities, set severity, generate or apply patches, or decide verification verdicts. The verdict comes only from the executed tests in `testing/` (see [docs/testing_contract.md](docs/testing_contract.md)).
- **AI patch suggestions are not implemented.** All patches come from the deterministic generator and still need human approval.
- If Ollama is down, slow, missing the model, or returns empty or malformed output, the API returns `available: false` with a reason, never invented text. Scanning, patching and verification are unaffected.

## P. Demo walkthrough

Start the backend and the frontend, then open <http://localhost:5173>.

1. **The vulnerable app.** Show `fixtures/vulnerable_app/app.py`: `/search` builds SQL with an f-string, and `/documents/<id>` returns any document without an ownership check (even though `can_view_document` exists and `/summary` uses it).
2. **Detection.** Go to **Projects**, choose **Create project** (Student Document Portal), then **Run scan**. Two findings appear: SQLi (CRITICAL) at `app.py:68-69` and IDOR (HIGH) on `get_document`.
3. **Finding details.** Open the SQLi finding: highlighted lines, the data-flow trace `term ← request.args.get("q")`, the explanation, and the severity rationale.
4. **Reproduce the exploit.** Go to **Attack Replay Lab**, choose SQL Injection, and click **Run exploit on original code**. The real responses show the private documents and synthetic user tokens leaking, and that `O'Brien` crashes the search with HTTP 500.
5. **Patch review.** Click **Scan project source**, then **Generate patch**. The diff shows the parameterised query.
6. **Patch application.** Enter your name and click **Approve & apply** (a backup is taken).
7. **Exploit replay.** Click **Run Proof-of-Fix**. Before the patch the exploit succeeded; after the patch it is blocked.
8. **Regression testing.** The same view shows the legitimate searches passing, including `O'Brien` now working. Verdict: **VERIFIED**.
9. **Patch rejection.** Switch the vulnerability to IDOR. Run the baseline (Alice can read Bob's private document). Generate the **Deny-all (deliberately over-restrictive demo)** patch, apply it, and run Proof-of-Fix. The verdict is **FAILED**: the exploit is blocked, but Alice can't read her own document and the teacher can't read their student's. Point out that the patch review page showed that the static re-scan considered it fine. Click **Roll back this patch and try another**, generate the **Server-side ownership check**, apply it, and replay. All 7 PrivilegeMap rules hold, so the verdict is **VERIFIED**.
10. **Verification report.** Open **Reports**, then **HTML**, for a printable report with findings, diff, every executed test and the known limitations.

Tip: **New fresh demo project** in the lab gives you a clean, unpatched copy at any time.

**Gauntlet + Forensics demo (about 3 minutes, on a fresh demo project):**
1. In the Lab, choose SQL Injection, run the exploit, then scan.
2. Pick **Naive blocklist (deliberately bypassable demo)**, approve it, then **Run Proof-of-Fix**. Expected result: **FAILED**. The summary card shows the original payload *blocked* but 5 variants *bypassing* the patch (case, whitespace, comment, position, UNION). Canary records exposed go from 3 to 3.
3. Click **Gauntlet** for the surviving-bypass panel (exact input, expected vs actual, the leaked records) and the matrix. Expand any row for evidence. The bypasses are now listed under **Preserved regression cases**.
4. Click **Exposure ledger** to see which actor got which record and fields, and how the UNION variant leaked `body` while the tautologies leaked `title`.
5. Roll back, apply the **Parameterised query**, and replay. Result: **VERIFIED**. The 5 saved bypasses are replayed automatically and now *blocked*; 0 records exposed after the patch.
6. Switch to IDOR. The deny-all patch blocks all 9 attack variants but breaks every legitimate-use variant, so it stays **FAILED**. The ownership check is **VERIFIED**, and in **Exposure Forensics** DOC-202 goes from exposed to Alice, Carol and Ms Rivera to not exposed, while each owner keeps access.

## Q. Security limitations

- **Two vulnerability classes only:** SQL injection (CWE-89) and IDOR (CWE-639).
- **Supported patterns only.** SQLi is detected in DB-API `.execute()` calls with f-string, `+`, `+=`, `%` or `.format()` SQL. IDOR is detected in Flask-style routes with a URL path parameter used in a lookup without an access check. Auto-patching covers f-string and `+` SQL, and IDOR where the module already has a two-argument access-check helper. Exact rules: [docs/architecture.md](docs/architecture.md#static-analysis-scope-what-the-scanner-understands).
- **Static analysis has blind spots.** It doesn't follow data across functions or files, ORMs, or custom middleware. *No findings does not mean secure.*
- **Dynamic verification runs only on the bundled fixture**, locally, on isolated copies with synthetic data. Uploaded code is never executed.
- **Exploit tests are specific payloads.** "Blocked" means these attacks are blocked, not every possible variant.
- **The Gauntlet is a fixed, validated variant set**, not a fuzzer. Surviving it does not prove resistance to every payload.
- **Forensics covers only the seeded synthetic canary records** and what actual responses returned. It is not a full database-exposure analysis.
- **AI is not authoritative.** It plays no part in detection, patching or verdicts. Its explanations come from a small local model (`gemma4:e2b`) and can be wrong, so always compare them with the scanner's evidence.
- **No authentication on the API.** It is a local demo tool, so don't expose it to a network.
- This produces a **verification report, not a security certification.** PatchProof does not claim universal detection or automated repair.

## R. Troubleshooting

| Problem | Fix |
|---|---|
| `/api/health` returns 503 `database_not_configured` | `.env` is missing or `DATABASE_URL` is empty. Put `.env` in the repo root (or `backend/`) and restart uvicorn. |
| Neon connection fails or times out | Check the URL in the Neon console. Make sure it starts with `postgresql://` and the password has no unescaped special characters. Free-tier computes sleep, so the first request may take a few seconds. |
| `alembic upgrade head` fails | Run it from `backend/` with the venv active. `relation already exists` means the tables already exist, so check `alembic current`. Never drop production tables to "fix" this. |
| Dashboard says "AI assistant: offline" | Expected if Ollama isn't running. Start the Ollama app (or run `ollama serve`), or ignore it (it's optional). Check with `curl http://localhost:11434/api/version`. |
| `/health/ollama` says the model isn't installed | Run `ollama pull <OLLAMA_MODEL>`. The name must match `ollama list` exactly (`gemma4:e2b`; a bare `llama3.2` matches `llama3.2:latest`). |
| `ollama` is "not recognized" in the terminal | Open a new terminal after installing (PATH is updated), or call `$env:LOCALAPPDATA\Programs\Ollama\ollama.exe` directly. |
| AI explanation says "did not answer within 60s" | The first request after a restart loads the model into memory and is slower. Click **Try again**. If it keeps happening, use a smaller model, or raise `OLLAMA_TIMEOUT_SECONDS` a little in `.env`. |
| AI answers are very slow | Check that `OLLAMA_MODEL` is the small `gemma4:e2b`, and close other GPU- or memory-heavy apps. `ollama ps` shows what is loaded. |
| Frontend shows "Cannot reach the backend" | Is uvicorn running on port 8000? Check `VITE_API_BASE_URL` in `frontend/.env` and restart `npm run dev` after editing it. |
| CORS error in the browser console | The page's origin must be in `FRONTEND_ORIGIN`. `http://127.0.0.1:5173` is **not** the same as `http://localhost:5173`. |
| Port 8000 or 5173 already in use | `netstat -ano | findstr :8000`, then stop that PID, or use `--port 8001` and update `VITE_API_BASE_URL`. Vite uses `strictPort`, so change it in `vite.config.ts` if needed. |
| Verification fails with "Could not start test runner" or `ModuleNotFoundError: flask` | The backend venv needs Flask: `pip install -r requirements.txt` installs it. Or set `TESTING_PYTHON` to an interpreter that has `testing/requirements.txt` installed. |
| `python -m testing.runner` says `No module named testing` | Run it from the **repository root**, not from inside `testing/`. |
| Verification returns `verification_not_possible` | Uploaded projects can't be verified (by design), or the patch hasn't been applied yet. |
| Generating a patch returns `patch_already_applied` | Roll back the earlier patch for that finding first (the patch page has a **Roll back** button). |
| Lab says no finding found | That project's working copy is already patched. Click **New fresh demo project**. |
