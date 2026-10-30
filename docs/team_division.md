# Team Division, Ownership and Git Workflow

## Ownership

| Path | Owner | Others may… |
|---|---|---|
| `backend/app/`, `backend/alembic/`, `backend/tests/`, `backend/requirements.txt` | **Diya** | read only |
| `docs/api_contract.md`, `.env.example` | **Diya** | propose changes via issue/PR comment |
| `frontend/` (everything) | **Chinmayee** | read only |
| `docs/frontend_integration.md` | **Chinmayee** | propose changes |
| `testing/`, `fixtures/` | **Dipto** | read only |
| `docs/testing_contract.md` | **Dipto** | propose changes |
| `README.md`, `docs/architecture.md`, `docs/team_division.md`, `docs/threat_model.md` | Shared | edit only your own section; announce in chat |
| `.gitignore`, `.gitattributes` | Shared (Diya coordinates) | ask Diya |

If you need a change in someone else's directory, **do not make it yourself**. Open an issue, or leave a comment describing the change, and tag the owner.

## Responsibilities

### Diya: backend and security engine
FastAPI app, Neon connection, SQLAlchemy models, Alembic migrations, all `/api` endpoints, the scanner (SQLi and IDOR), patch generation, apply and rollback, the verification adapter and engine (which *call* Dipto's runner), Ollama integration, reports, and the backend tests.
**Must not:** edit `frontend/`, `testing/` or `fixtures/`, or re-implement exploit and regression tests in the backend.

### Chinmayee: frontend
All React/TypeScript/Tailwind code: dashboard, projects, scanner, findings, code evidence, patch review and approval, Attack Replay Lab, verification results, reports, and API integration through `src/services/api.ts`.
**Must not:** edit backend Python, models, migrations, `testing/` or `fixtures/`. Work against mock mode until the needed endpoints exist.

### Dipto: security testing and verification
The deliberately vulnerable Flask fixture, synthetic seed data, SQLi and IDOR exploit scenarios, regression tests, PrivilegeMap, reference variants (correct and over-restrictive), verdict rules, the runner CLI and its JSON schema, and the runner's own pytest suite.
**Must not:** edit `backend/`, the Neon schema or `frontend/`.

## Integration points (the only places the work meets)

| Producer → Consumer | Interface | Document |
|---|---|---|
| Diya → Chinmayee | HTTP JSON API under `/api` | `docs/api_contract.md` + `/docs` (Swagger) |
| Dipto → Diya | `python -m testing.runner` CLI and its JSON output | `docs/testing_contract.md` |
| Dipto → Diya | `fixtures/vulnerable_app/` contents (copied into projects) | `backend/app/services/storage.py: FIXTURES` registry |

**Dependency notes**
- If Dipto renames the fixture directory or adds a new fixture, Diya must update the `FIXTURES` registry.
- If Dipto changes the scenario names (`sqli`, `idor`), Diya's request validation and Chinmayee's dropdown must change too.
- If Diya changes a response shape, Chinmayee updates `src/types/api.ts`, and Diya regenerates `frontend/src/services/mockData.json` from a real run.

## Independent verification commands

```powershell
# Dipto: testing framework (repo root)
python -m pytest testing/tests -q

# Diya: backend unit + API tests (they run Dipto's runner as a subprocess)
cd backend; .\venv\Scripts\python -m pytest -q

# Chinmayee: type check + production build
cd frontend; npm run build
```

## Git workflow

Branches:
- `main`: stable and demo-ready. Never commit directly during the hackathon.
- `feature/backend-diya`, `feature/frontend-chinmayee`, `feature/testing-dipto`

Before opening a PR to `main`:
1. `git pull origin main` and merge it into your branch. Resolve conflicts (there should be none if you stayed in your directories).
2. Run your verification command above, and the others if your change touches an interface.
3. Check that `git status` and the PR's changed files only touch your directories.
4. Never commit `.env`, `venv/`, `.venv-*/`, `node_modules/`, `dist/`, `backend/storage/` or `*.sqlite3` (they are already in `.gitignore`).
5. Merge only when the tests pass. Don't merge half-finished features into `main`.

Contract changes (API, testing JSON, routes): announce them in the team chat **before** merging, and update the relevant doc in the same PR.
