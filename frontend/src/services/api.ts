// Single place where the frontend talks to the backend.
// Set VITE_USE_MOCKS=true to use services/mock.ts instead (a banner then marks all data as mock).
import type {
  AIExplanation,
  DashboardSummary,
  Finding,
  FindingDetail,
  FixtureInfo,
  Health,
  OllamaStatus,
  Patch,
  Project,
  ProjectDetail,
  ReportListItem,
  ScanSummary,
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

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let res: Response;
  try {
    res = await fetch(`${API_BASE}${path}`, init);
  } catch {
    throw new ApiError(0, "network_error", `Cannot reach the backend at ${API_BASE}. Is uvicorn running?`);
  }
  const body = await res.json().catch(() => null);
  if (!res.ok) {
    const err = body?.error;
    throw new ApiError(res.status, err?.code ?? "http_error", err?.message ?? `HTTP ${res.status}`, err?.details);
  }
  return body as T;
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
  listReports: () => request<ReportListItem[]>("/reports"),
  reportUrl: (id: string, format: "json" | "html"): string | null => `${API_BASE}/reports/${id}?format=${format}`,
};

export type Api = typeof realApi;
export const api: Api = USE_MOCKS ? mockApi : realApi;
