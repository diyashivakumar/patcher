// MOCK MODE (VITE_USE_MOCKS=true): lets the UI be built without the backend.
// mockData.json was captured from a REAL backend run (see docs/frontend_integration.md),
// so shapes match the contract exactly. The layout shows a "MOCK DATA" banner in this mode.
import type { Api } from "./api";
import type { FindingDetail, Patch, VerificationRunDetail, VulnType } from "../types/api";
import raw from "./mockData.json";

const data = raw as any;
const DEFAULT_STRATEGY: Record<VulnType, string> = { sqli: "parameterized_query", idor: "ownership_check" };

const patches = new Map<string, { key: string; patch: Patch }>();
const runs = new Map<string, VerificationRunDetail>();

const wait = <T>(value: T, ms = 350): Promise<T> =>
  new Promise((resolve) => setTimeout(() => resolve(structuredClone(value)), ms));

class MockError extends Error {
  status = 409;
  code = "mock_unsupported";
}

function findingById(id: string): FindingDetail {
  const f = data.findingDetails[id];
  if (!f) throw new MockError("Finding not found in mock data");
  return {
    ...f,
    patches: [...patches.values()]
      .filter((p) => p.patch.finding_id === id)
      .map(({ patch }) => ({ id: patch.id, strategy: patch.strategy, status: patch.status, created_at: patch.created_at })),
  };
}

function patchEntry(id: string) {
  const entry = patches.get(id);
  if (!entry) throw new MockError("Patch not found in mock data");
  return entry;
}

export const mockApi: Api = {
  health: () => wait({ status: "ok", database: "mock", version: "mock" }),
  ollamaStatus: () => wait(data.ollama),
  dashboard: () => wait(data.dashboard),
  fixtures: () => wait(data.fixtures),
  listProjects: () => wait([data.project]),
  getProject: () => wait(data.project),
  createProject: () => wait(data.project),
  uploadProject: () => Promise.reject(new MockError("Uploads are not available in mock mode")),
  runScan: () => wait(data.scan, 700),
  getScan: () => wait(data.scan),
  getScanFindings: () => wait(data.findings),
  getFinding: (id) => wait(findingById(id)),
  explainFinding: () =>
    wait({ available: false, model: null, text: null, message: "Mock mode: Ollama is not called.", advisory: "" }),
  generatePatch: (findingId, strategy) => {
    const finding = findingById(findingId);
    const key = `${finding.vuln_type}:${strategy ?? DEFAULT_STRATEGY[finding.vuln_type]}`;
    const template: Patch | undefined = data.proposedPatches[key];
    if (!template) return Promise.reject(new MockError(`No mock patch for ${key}`));
    const active = [...patches.values()].find(
      (p) => p.patch.finding_id === findingId && ["APPLIED", "VERIFIED", "REJECTED"].includes(p.patch.status),
    );
    if (active) return Promise.reject(new MockError("A patch is still applied for this finding. Roll it back first."));
    const patch = { ...template, id: crypto.randomUUID(), verification_runs: [] };
    patches.set(patch.id, { key, patch });
    return wait(patch);
  },
  getPatch: (id) => wait(patchEntry(id).patch),
  applyPatch: (id, approvedBy) => {
    const entry = patchEntry(id);
    entry.patch = { ...data.appliedPatches[entry.key], id, approved_by: approvedBy, verification_runs: [] };
    return wait(entry.patch);
  },
  rollbackPatch: (id) => {
    const entry = patchEntry(id);
    entry.patch = { ...entry.patch, status: "ROLLED_BACK", rolled_back_at: new Date().toISOString() };
    return wait(entry.patch);
  },
  runBaseline: (_projectId, scenario) => {
    const run = { ...data.baseline[scenario], id: crypto.randomUUID(), created_at: new Date().toISOString() };
    runs.set(run.id, run);
    return wait(run, 900);
  },
  runProofOfFix: (patchId) => {
    const entry = patchEntry(patchId);
    if (entry.patch.status === "PROPOSED") return Promise.reject(new MockError("Apply the patch first"));
    const run = { ...data.runs[entry.key], id: crypto.randomUUID(), patch_id: patchId, created_at: new Date().toISOString() };
    runs.set(run.id, run);
    entry.patch = {
      ...entry.patch,
      status: run.verdict === "VERIFIED" ? "VERIFIED" : "REJECTED",
      verification_runs: [{ id: run.id, kind: run.kind, status: run.status, verdict: run.verdict, created_at: run.created_at }],
    };
    run.patch_status = entry.patch.status;
    return wait(run, 1200);
  },
  listRuns: () => wait([...runs.values()].reverse()),
  getRun: (id) => {
    const run = runs.get(id);
    return run ? wait(run) : Promise.reject(new MockError("Run not found in mock data (mock state resets on reload)"));
  },
  listReports: () =>
    wait(
      [...runs.values()].reverse().map((r) => ({
        report_id: r.id,
        kind: r.kind,
        scenario: r.scenario,
        status: r.status,
        verdict: r.verdict,
        original_vulnerability_reproduced: r.original_vulnerability_reproduced,
        project_id: r.project_id,
        patch_id: r.patch_id,
        patch_strategy: r.patch_id ? patches.get(r.patch_id)?.patch.strategy ?? null : null,
        created_at: r.created_at,
      })),
    ),
  reportUrl: () => null,
};
