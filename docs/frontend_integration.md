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
| `/` | Dashboard | `GET /dashboard/summary`, `/health`, `/health/ollama` |
| `/projects` | Projects (create from fixture, ZIP upload, list) | `GET /fixtures`, `GET /projects`, `POST /projects`, `POST /projects/upload` |
| `/projects/:id` | Project scanner and scan history | `GET /projects/{id}`, `POST /scans` |
| `/scans/:id` | Scan results / findings list | `GET /scans/{id}`, `GET /scans/{id}/findings` |
| `/findings/:id` | Finding details, code evidence, patch generation, AI explanation | `GET /findings/{id}`, `POST /patches/generate`, `POST /findings/{id}/ai-explanation` |
| `/patches/:id` | Patch review: diff, before/after, approval, rollback, Proof-of-Fix | `GET /patches/{id}`, `POST …/apply`, `POST …/rollback`, `POST /verification/run` |
| `/replay` | Attack Replay Lab (guided 5-step demo) | `POST /projects`, `POST /verification/run` (baseline and Proof-of-Fix), `POST /scans`, `POST /patches/*` |
| `/verification/:id` | Verification result and evidence | `GET /verification/{id}`, report links |
| `/reports` | Verification reports | `GET /reports`, `/reports/{id}?format=html|json` |

## Rules for the UI

1. **Never invent results.** Every verdict, count and test row on screen must come from an API response. Show `—`, an empty state or an error when data is missing.
2. Show errors from `error.message` in the standard error body (the `ApiError` class in `services/api.ts` already parses it).
3. Applying a patch requires an explicit approval step: the approver's name plus a review checkbox.
4. Label AI text as advisory, using the `advisory` string from the API.
5. Uploaded projects can't be verified (`verification_supported: false`). Explain this instead of hiding the button silently.

## CORS

The backend allows the origin(s) in `FRONTEND_ORIGIN` (default `http://localhost:5173`). If you run Vite on another port or host, add it there. For example, opening the app at `http://127.0.0.1:5173` is a *different* origin from `http://localhost:5173`.
