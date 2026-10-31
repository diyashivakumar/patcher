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

// A live verification run (with gauntlet + forensics) per strategy, so a mock Proof-of-Fix
// produces the same rich evidence as the backend.
const RICH_BY_KEY: Record<string, string> = {
  "sqli:parameterized_query": "sqli_verified",
  "sqli:naive_blocklist_demo": "sqli_failed",
  "idor:ownership_check": "idor_verified",
  "idor:deny_all_demo": "idor_failed",
};

// Seed the app "mid-investigation": recent rich runs + their patches are present on first load,
// so Dashboard, Reports, Variant Gauntlet and Exposure Forensics render populated with no clicks.
(function seed() {
  const rich: Record<string, VerificationRunDetail> = data.richRuns ?? {};
  const labels = ["sqli_verified", "idor_verified", "sqli_failed", "idor_failed"];
  labels.forEach((label, i) => {
    const run = rich[label];
    if (!run) return;
    run.created_at = new Date(Date.now() - (6 + i * 37) * 60_000).toISOString();
    runs.set(run.id, run);
  });
  for (const [id, patch] of Object.entries((data.richPatches ?? {}) as Record<string, Patch>)) {
    patches.set(id, { key: `${patch.vuln_type}:${patch.strategy}`, patch });
  }
})();

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
    const template = data.richRuns?.[RICH_BY_KEY[entry.key]] ?? data.runs[entry.key];
    const run = { ...template, id: crypto.randomUUID(), patch_id: patchId, created_at: new Date().toISOString() };
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
  listRegressionCases: (scenario) =>
    wait((data.regressionCases ?? []).filter((c: { scenario: string }) => !scenario || c.scenario === scenario)),
  chainImpact: () => wait(data.chainImpact, 900),
  hostPorts: () =>
    wait({
      supported: true,
      os: "Windows",
      inspected_at: new Date().toISOString(),
      scope_note: "Inspection is local to this machine only; no external hosts are contacted.",
      warning: null,
      entries: [
        { protocol: "TCP", local_address: "0.0.0.0", port: 445, pid: 4, process_name: "System", process_path: null,
          binding_scope: "all_interfaces", risk: "HIGH",
          risk_reason: "SMB is exposed on all interfaces (0.0.0.0/::). Sensitive services should usually be bound to localhost or firewalled." },
        { protocol: "TCP", local_address: "0.0.0.0", port: 3389, pid: 920, process_name: "svchost", process_path: "C:/Windows/System32/svchost.exe",
          binding_scope: "all_interfaces", risk: "HIGH",
          risk_reason: "RDP is exposed on all interfaces (0.0.0.0/::). Sensitive services should usually be bound to localhost or firewalled." },
        { protocol: "TCP", local_address: "192.168.1.20", port: 8081, pid: 5120, process_name: "node", process_path: "C:/Program Files/nodejs/node.exe",
          binding_scope: "specific_interface", risk: "MEDIUM",
          risk_reason: "Bound to a specific non-loopback interface, so it is reachable from that network." },
        { protocol: "TCP", local_address: "127.0.0.1", port: 11434, pid: 7200, process_name: "ollama", process_path: "C:/Users/demo/ollama.exe",
          binding_scope: "localhost", risk: "LOW",
          risk_reason: "Expected local service (Ollama) bound to localhost; not reachable from other machines." },
        { protocol: "TCP", local_address: "127.0.0.1", port: 8000, pid: 6010, process_name: "python", process_path: "C:/Users/demo/venv/python.exe",
          binding_scope: "localhost", risk: "LOW",
          risk_reason: "Expected local service (Dev HTTP/API) bound to localhost; not reachable from other machines." },
        { protocol: "UDP", local_address: "127.0.0.1", port: 53, pid: 1400, process_name: "dns", process_path: null,
          binding_scope: "localhost", risk: "INFO",
          risk_reason: "Listener bound to localhost only; not reachable from other machines." },
      ],
      summary: { total: 6, tcp: 5, udp: 1, localhost: 3, external: 3, by_risk: { HIGH: 2, MEDIUM: 1, LOW: 2, INFO: 1 } },
    }, 600),
  runSiteCheck: (url) =>
    wait({
      id: crypto.randomUUID(), url, host: (url.replace(/^https?:\/\//, "").split("/")[0]) || "example.com",
      authorized: true, status: "COMPLETED" as const, final_url: url, resolved_ips: ["93.184.216.34"],
      redirect_chain: [{ url, status: 200 }],
      posture: { counts: { PASS: 5, WARNING: 3, INFO: 2, ERROR: 0 }, summary: "several improvements recommended" },
      checks: [
        { name: "DNS resolution", status: "INFO", evidence: "93.184.216.34", explanation: "Resolves to 1 public address.", remediation: null, checked_at: null },
        { name: "HTTPS supported", status: "PASS", evidence: "certificate CN=example.com", explanation: "The site completed a valid TLS handshake.", remediation: null, checked_at: null },
        { name: "Certificate validity", status: "PASS", evidence: "88 days left", explanation: "The certificate is valid and not near expiry.", remediation: null, checked_at: null },
        { name: "Header: strict-transport-security", status: "WARNING", evidence: "not set", explanation: "Enforces HTTPS for future visits (HSTS).", remediation: "Add the strict-transport-security response header.", checked_at: null },
        { name: "Header: content-security-policy", status: "WARNING", evidence: "not set", explanation: "Restricts where scripts/styles load from (XSS).", remediation: "Add the content-security-policy response header.", checked_at: null },
        { name: "Cookie security", status: "PASS", evidence: "no cookies", explanation: "No cookies were set on this response.", remediation: null, checked_at: null },
        { name: "Technology disclosure", status: "WARNING", evidence: "Server: ECS", explanation: "Server/technology version headers are exposed.", remediation: "Suppress or genericise Server headers.", checked_at: null },
      ],
      error: null,
      disclaimer: "PatchProof performs basic non-invasive configuration checks. This is not a full penetration test or guarantee that a website is secure.",
      created_at: new Date().toISOString(), updated_at: new Date().toISOString(),
    }, 1100),
  listSiteChecks: () => wait([]),
  getSiteCheck: () => Promise.reject(new MockError("Site-check details need the real backend")),
  getReport: () => Promise.reject(new MockError("Report details need the real backend")),
  downloadReport: () => Promise.reject(new MockError("Report downloads need the real backend")),
  reportUrl: () => null,
};
