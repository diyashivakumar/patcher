# Frontend Integration Guide

**Owner:** Chinmayee (`frontend/`). The API contract is [api_contract.md](api_contract.md) and is owned by Diya.

## Setup (Windows PowerShell)

```powershell
cd frontend
npm install
Copy-Item .env.example .env      # then edit if needed
npm run dev                      # http://localhost:5173
```

Other scripts: `npm run build` (type-checks, then produces a production bundle in `dist/`), `npm run typecheck`, `npm run preview`.

## Environment variables (`frontend/.env`)

| Variable | Default | Purpose |
|---|---|---|
| `VITE_API_BASE_URL` | `http://localhost:8000/api` | Backend base URL |
| `VITE_USE_MOCKS` | `false` | `true` means no backend is needed. Data comes from `src/services/mockData.json` |

## Working without the backend (mock mode)

Set `VITE_USE_MOCKS=true` and restart `npm run dev`. Every page then shows an amber **MOCK DATA MODE** banner, so mock results can never be mistaken for real ones.

`src/services/mockData.json` was **captured from a real backend run**, so its shapes match the contract exactly. `src/services/mock.ts` replays it with a small state machine. Generating, applying, verifying and rolling back patches change status the same way the backend does. Uploads and HTML reports are disabled in mock mode. If the contract changes, ask Diya to regenerate the mock data from a real run.

## Code layout

```
src/
  types/api.ts          TypeScript mirror of the backend schemas (keep in sync with api_contract.md)
  services/api.ts       The ONLY place that calls fetch(). Switches to mock.ts when VITE_USE_MOCKS=true
  services/mock.ts      Mock implementation + mockData.json
  hooks/useApi.ts       useApi (load on mount) and useAction (button-triggered calls with busy/error)
  layouts/AppLayout.tsx Sidebar, mock banner
  components/           ui.tsx (cards, badges, buttons), CodeBlock.tsx (code + diff), RunView.tsx (verdict + test tables)
  pages/                One file per route (see below)
```

## Routes

| Route | Page | Backend calls |
|---|---|---|
| `/` | Dashboard: stats, open findings, recent scans and verification results, quick actions | `GET /dashboard/summary`, `GET /projects`, `GET /reports`, `/health`, `/health/ollama` |
| `/projects` | Projects (create from fixture, ZIP upload with client-side checks, list) | `GET /fixtures`, `GET /projects`, `POST /projects`, `POST /projects/upload` |
| `/projects/:id` | Project overview and scan history | `GET /projects/{id}`, `POST /scans` |
| `/scanner` | Scanner: pick a project, see the detectors, start a scan, see the result | `GET /projects`, `POST /scans` |
| `/findings` | All open findings (each project's latest scan) with severity/type filters | `GET /projects`, `GET /scans/{id}/findings` per project |
| `/scans/:id` | Findings for one scan, with filters | `GET /scans/{id}`, `GET /scans/{id}/findings` |
| `/findings/:id` | Finding details, code evidence, patch generation, AI explanation | `GET /findings/{id}`, `POST /patches/generate`, `POST /findings/{id}/ai-explanation` |
| `/patches/:id` | Patch review: diff, original/proposed, approval, rollback, Proof-of-Fix | `GET /patches/{id}`, `POST …/apply`, `POST …/rollback`, `POST /verification/run` |
| `/replay` | Attack Replay Lab: Before patch → Patch → After patch (same attack, before/after table) → Final verdict | `POST /projects`, `POST /verification/run` (baseline and Proof-of-Fix), `POST /scans`, `POST /patches/*` |
| `/verification/:id` | Verification result: verdict, what was verified, patch diff, before/after table, evidence, downloads | `GET /verification/{id}`, `GET /reports/{id}`, report downloads |
| `/reports` | Verification reports: view, open HTML, download HTML/JSON | `GET /reports`, `GET /reports/{id}?format=html|json` |

The layout calls `GET /health` once on load and shows a red **Backend unreachable** banner with Retry, or an amber banner if the API is up but its database is down.

## Backend limitations the frontend works around (not bugs; documented, not invented)

| Need | Backend reality | Frontend behaviour |
|---|---|---|
| A list of all findings | No `GET /findings` list endpoint | `/findings` calls `GET /projects`, then `GET /scans/{latest}/findings` per project (one request per scanned project) |
| A finding status (open/fixed) | Findings have no status field | "Open" means present in the project's latest scan. Re-scan after patching to update. The finding page lists its patches and their status |
| Choosing the scan type | `POST /scans` always runs both detectors | The Scanner page lists both detectors as informational, not as a selector that would do nothing |
| Scan progress | Scans are synchronous with no progress API | A spinner and elapsed seconds; no invented percentage |
| "Open findings" on the dashboard | `total_findings` counts findings from every scan, including superseded ones | The dashboard sums `latest_scan.findings_count` from `GET /projects` |

## Verdicts are never computed in the browser

The verdict badge, the three checks (reproduced / blocked / preserved) and the reasons come straight from the verification run. The before/after table only puts the runner's per-test results side by side. The Lab's final-step icon follows the backend verdict, so a FAILED run shows a red cross, not a tick.

## Browser-tested against the real Neon-backed backend (2026-10-30)

| Scenario | Result |
|---|---|
| Empty database: dashboard, Findings, Scanner empty states | Real zeros and empty-state messages with next steps |
| SQLi: create project → Scanner → filtered findings → finding detail → parameterised patch → approve (gated on name + checkbox) → Proof-of-Fix | **VERIFIED**; verification page shows the report summary and before/after table |
| IDOR in the Lab: baseline (exploit reproduced) → deny-all patch → approve → replay | **FAILED**: exploits blocked, but 3 legitimate-use tests "Broken"; rejection explained |
| Roll back → ownership-check patch → approve → replay | **VERIFIED** (4/4 security, 4/4 regression) |
| Reports list | All 4 runs with real verdicts; HTML/JSON endpoints return 200 with correct content types |
| Non-ZIP file selected | Blocked in the browser: "Only .zip archives are accepted." |
| ZIP containing `../../evil.py` | Backend rejection shown: "Unsafe path in ZIP (path traversal attempt)" |
| Backend stopped, then restarted | Red banner and error box, no stale or fake numbers; Retry restores everything |
| AI explanation (Ollama gemma4:e2b) | Works, with the advisory label |

Not clicked in the browser: the **⤓ HTML / ⤓ JSON** download buttons (they save files locally; their endpoints and CORS were checked with curl). Ollama-unavailable handling was browser-tested in an earlier session using a missing model.

Response times are noticeably longer on Neon than on a local DB. Generating a patch, applying it, or scanning takes roughly 3–10 s, because each request makes several round trips to Neon. Every button shows a spinner meanwhile.

## Rules for the UI

1. **Never invent results.** Every verdict, count and test row on screen must come from an API response. Show `—`, an empty state or an error when data is missing.
2. Show errors from `error.message` in the standard error body (the `ApiError` class in `services/api.ts` already parses it).
3. Applying a patch requires an explicit approval step: the approver's name plus a review checkbox.
4. Label AI text as advisory, using the `advisory` string from the API.
5. Uploaded projects can't be verified (`verification_supported: false`). Explain this instead of hiding the button silently.

## CORS

The backend allows the origin(s) in `FRONTEND_ORIGIN` (default `http://localhost:5173`). If you run Vite on another port or host, add it there. For example, opening the app at `http://127.0.0.1:5173` is a *different* origin from `http://localhost:5173`.
