// Single place where the frontend talks to the backend.
// Set VITE_USE_MOCKS=true to use services/mock.ts instead (a banner then marks all data as mock).
import type {
  AIExplanation,
  DashboardSummary,
  Finding,
  FindingDetail,
  FixtureInfo,
  Health,
  HostPortsResult,
  OllamaStatus,
  Patch,
  Project,
  ProjectDetail,
  ChainImpactResult,
  RegressionCase,
  Report,
  ReportListItem,
  ScanSummary,
  SiteCheck,
  VerificationRun,
  VerificationRunDetail,
  VulnType,
} from "../types/api";
import { mockApi } from "./mock";

export const API_BASE = (import.meta.env.VITE_API_BASE_URL as string | undefined) ?? "http://localhost:8000/api";
export const USE_MOCKS = import.meta.env.VITE_USE_MOCKS === "true";

export class ApiError extends Error {
  constructor(
    public status: number,
    public code: string,
    message: string,
    public details?: unknown,
  ) {
    super(message);
  }
}

// Generous enough for an AI explanation (backend gives Ollama 60 s) or a verification run.
const TIMEOUT_MS = 120_000;

async function send(path: string, init?: RequestInit): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
  try {
    return await fetch(`${API_BASE}${path}`, { ...init, signal: controller.signal });
  } catch (e) {
    if ((e as Error).name === "AbortError") {
      throw new ApiError(0, "timeout", `The backend did not respond within ${TIMEOUT_MS / 1000}s.`);
    }
    throw new ApiError(0, "network_error", `Cannot reach the backend at ${API_BASE}. Is uvicorn running?`);
  } finally {
    clearTimeout(timer);
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await send(path, init);
  const body = await res.json().catch(() => undefined);
  if (!res.ok) {
    const err = body?.error;
    throw new ApiError(res.status, err?.code ?? "http_error", err?.message ?? `HTTP ${res.status}`, err?.details);
  }
  if (body === undefined || body === null) {
    throw new ApiError(res.status, "invalid_response", `The backend returned an empty or non-JSON response for ${path}.`);
  }
  return body as T;
}

/** Save a report to disk via a Blob (cross-origin <a download> is ignored by browsers). */
async function downloadReport(id: string, format: "json" | "html") {
  const res = await send(`/reports/${id}?format=${format}`);
  if (!res.ok) throw new ApiError(res.status, "http_error", `Report download failed (HTTP ${res.status}).`);
  const url = URL.createObjectURL(await res.blob());
  const a = Object.assign(document.createElement("a"), { href: url, download: `patchproof-report-${id.slice(0, 8)}.${format}` });
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

const post = <T>(path: string, data: unknown) =>
  request<T>(path, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(data) });

const realApi = {
  health: () => request<Health>("/health"),
  ollamaStatus: () => request<OllamaStatus>("/health/ollama"),
  dashboard: () => request<DashboardSummary>("/dashboard/summary"),
  fixtures: () => request<FixtureInfo[]>("/fixtures"),
  listProjects: () => request<Project[]>("/projects"),
  getProject: (id: string) => request<ProjectDetail>(`/projects/${id}`),
  createProject: (data: { name: string; description?: string; fixture_name: string }) =>
    post<ProjectDetail>("/projects", data),
  uploadProject: (name: string, description: string, file: File) => {
    const form = new FormData();
    form.append("name", name);
    if (description) form.append("description", description);
    form.append("file", file);
    return request<ProjectDetail>("/projects/upload", { method: "POST", body: form });
  },
  runScan: (projectId: string) => post<ScanSummary>("/scans", { project_id: projectId }),
  getScan: (id: string) => request<ScanSummary>(`/scans/${id}`),
  getScanFindings: (id: string) => request<Finding[]>(`/scans/${id}/findings`),
  getFinding: (id: string) => request<FindingDetail>(`/findings/${id}`),
  explainFinding: (id: string) => post<AIExplanation>(`/findings/${id}/ai-explanation`, {}),
  generatePatch: (findingId: string, strategy?: string) =>
    post<Patch>("/patches/generate", { finding_id: findingId, strategy: strategy ?? null }),
  getPatch: (id: string) => request<Patch>(`/patches/${id}`),
  applyPatch: (id: string, approvedBy: string) =>
    post<Patch>(`/patches/${id}/apply`, { approved: true, approved_by: approvedBy }),
  rollbackPatch: (id: string, reason: string) => post<Patch>(`/patches/${id}/rollback`, { reason }),
  runBaseline: (projectId: string, scenario: VulnType) =>
    post<VerificationRunDetail>("/verification/run", { project_id: projectId, scenario }),
  runProofOfFix: (patchId: string) => post<VerificationRunDetail>("/verification/run", { patch_id: patchId }),
  listRuns: (params: { project_id?: string; patch_id?: string; kind?: string } = {}) => {
    const qs = new URLSearchParams(Object.entries(params).filter(([, v]) => v) as [string, string][]);
    return request<VerificationRun[]>(`/verification${qs.size ? `?${qs}` : ""}`);
  },
  getRun: (id: string) => request<VerificationRunDetail>(`/verification/${id}`),
  listRegressionCases: (scenario?: VulnType) =>
    request<RegressionCase[]>(`/regression-cases${scenario ? `?scenario=${scenario}` : ""}`),
  listReports: () => request<ReportListItem[]>("/reports"),
  getReport: (id: string) => request<Report>(`/reports/${id}`),
  downloadReport: (id: string, format: "json" | "html"): Promise<void> => downloadReport(id, format),
  reportUrl: (id: string, format: "json" | "html"): string | null => `${API_BASE}/reports/${id}?format=${format}`,
  chainImpact: (projectId?: string) => post<ChainImpactResult>("/challenge/chain-impact", projectId ? { project_id: projectId } : {}),
  hostPorts: () => request<HostPortsResult>("/host/ports"),
  runSiteCheck: (url: string, authorized: boolean) => post<SiteCheck>("/site-checks", { url, authorized }),
  listSiteChecks: () => request<SiteCheck[]>("/site-checks"),
  getSiteCheck: (id: string) => request<SiteCheck>(`/site-checks/${id}`),
};

export type Api = typeof realApi;
export const api: Api = USE_MOCKS ? mockApi : realApi;
