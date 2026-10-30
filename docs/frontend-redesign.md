# PatchProof command-centre redesign

## Scope

The existing React/Vite frontend now uses a shared cyan/violet command-centre theme, glass panels, responsive navigation, real backend/AI connection checks, consistent page headings, and accessible focus states. The dashboard combines existing summary metrics with an SVG relationship graph, severity distribution, verification outcomes, recent investigations, and latest regression evidence. Projects and Reports use investigation cards; findings support text search alongside existing filters; scan results include severity and telemetry panels.

No backend, database, API contracts, mock fixtures, or verification logic changed. Existing patch approval, rollback, split diff, playground, and report capabilities are retained. The repository has no Gauntlet, Forensics, Kill-Chain, Fix Court, or Live Attack Timeline implementation; no placeholder routes were added.

## Data semantics

- The topology connects only recorded project, latest-scan finding, report, and patch relationships. It does not infer finding-to-patch relationships or attack propagation.
- The graph displays up to three projects, two findings per project, and two report branches per project. Its caption states the displayed project count; the project directory exposes the rest.
- Dashboard aggregate severity and proof counts come from the existing summary endpoint. Open findings retain the original latest-scan calculation. Rejected patches and failed proof verdicts keep their distinct meanings.
- Activity severity and exposure/bypass metrics are explicitly unavailable where absent from the API.
- Mock mode remains clearly labeled. Its summary is a captured snapshot, while its run/report lists contain session-created mock runs, as in the existing mock service.
- HTML/JSON downloads use the existing API download function. Demo mode disables them because the existing mock service does not implement downloads.

## Validation

- `npm run typecheck` and `npm run build` pass.
- Browser-checked every existing route: `/`, `/projects`, `/projects/:projectId`, `/scanner`, `/scans/:scanId`, `/findings`, `/findings/:findingId`, `/patches/:patchId`, `/replay`, `/verification/:runId`, `/reports`.
- Exercised mock scan execution, finding text search, patch generation, split diff, approval/application, Proof-of-Fix, keyboard evidence expansion, baseline replay, and the continuation anchor.
- Checked dashboard widths 375, 390, 430, 768, 1024, and 1440; no page-wide horizontal overflow. The graph and evidence tables retain their own horizontal viewports.
- Checked desktop navigation collapse, mobile drawer navigation, Escape dismissal, and route scroll reset. Motion has a reduced-motion override.
- No application console errors during mock checks. React Router emits its existing v7 migration notices.
- The real backend at `localhost:8000` is unavailable. Verified real API mode's disconnected/error state, without switching it to mock data. Live verification, actual report file contents/downloads, and live rollback could not be exercised.
