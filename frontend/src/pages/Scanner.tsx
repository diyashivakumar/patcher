import { CheckCircle2, Database, KeyRound, Loader2, ScanSearch } from "lucide-react";
import { useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { Button, Card, Empty, ErrorBox, fmtDate, Loading, PageHeader, SeverityBadge } from "../components/ui";
import { useAction, useApi } from "../hooks/useApi";
import { api } from "../services/api";
import type { ScanSummary } from "../types/api";

const DETECTORS = [
  { icon: Database, name: "SQL Injection (CWE-89)", detail: "execute() calls whose SQL is built with f-strings, +, % or .format()" },
  { icon: KeyRound, name: "Broken Access Control / IDOR (CWE-639)", detail: "routes that load a record by URL id without an ownership/permission check" },
];

/** Elapsed-time counter. The backend scan is synchronous and reports no progress, so no fake percentage. */
function Elapsed({ running }: { running: boolean }) {
  const [s, setS] = useState(0);
  useEffect(() => {
    if (!running) return;
    setS(0);
    const t = setInterval(() => setS((x) => x + 1), 1000);
    return () => clearInterval(t);
  }, [running]);
  return running ? <span className="tabular-nums">{s}s</span> : null;
}

export function Scanner() {
  const [params, setParams] = useSearchParams();
  const projects = useApi(() => api.listProjects());
  const scan = useAction();
  const [result, setResult] = useState<ScanSummary | null>(null);
  const projectId = params.get("project") ?? projects.data?.[0]?.id ?? "";
  const project = projects.data?.find((p) => p.id === projectId);

  const start = async () => {
    setResult(null);
    const r = await scan.run(() => api.runScan(projectId));
    if (r) { setResult(r); void projects.reload(); }
  };

  return (
    <>
      <PageHeader title="Scanner" subtitle="Static analysis of the project's current working copy using Python's AST." />
      <ErrorBox error={projects.error} onRetry={projects.reload} />
      {projects.loading && !projects.data && <Loading />}
      {projects.data?.length === 0 && (
        <Card><Empty>No projects to scan. <Link className="text-sky-400 hover:underline" to="/projects">Create a project</Link> first.</Empty></Card>
      )}
      {!!projects.data?.length && (
        <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
          <Card title="1 · Choose what to scan">
            <label className="mb-1 block text-xs text-slate-400" htmlFor="scan-project">Project</label>
            <select id="scan-project" value={projectId} onChange={(e) => { setResult(null); setParams({ project: e.target.value }); }}
              className="mb-4 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm">
              {projects.data.map((p) => <option key={p.id} value={p.id}>{p.name} · {p.source_type} · {p.scan_count} scan(s)</option>)}
            </select>
            <div className="mb-1 text-xs text-slate-400">Detectors (both run on every scan — the backend has no per-detector option)</div>
            <ul className="mb-4 space-y-2">
              {DETECTORS.map(({ icon: Icon, name, detail }) => (
                <li key={name} className="flex gap-3 rounded-lg border border-slate-800 bg-slate-950/60 p-3">
                  <Icon className="mt-0.5 h-4 w-4 shrink-0 text-sky-400" />
                  <div><div className="text-sm text-slate-200">{name}</div><div className="text-xs text-slate-500">{detail}</div></div>
                </li>
              ))}
            </ul>
            <Button onClick={start} busy={scan.busy} disabled={!projectId}><ScanSearch className="h-4 w-4" />Start scan</Button>
          </Card>

          <Card title="2 · Result">
            {scan.busy && (
              <div className="flex items-center gap-2 text-sm text-slate-300">
                <Loader2 className="h-4 w-4 animate-spin text-sky-400" /> Scanning {project?.file_count} file(s)… <Elapsed running={scan.busy} />
              </div>
            )}
            <ErrorBox error={scan.error} />
            {!scan.busy && !result && !scan.error && (
              <p className="text-sm text-slate-400">
                {project?.latest_scan ? <>Last scanned {fmtDate(project.latest_scan.started_at)} with {project.latest_scan.findings_count} finding(s). </> : "Not scanned yet. "}
                Start a scan to analyse the current source.
              </p>
            )}
            {result && (
              <div className="space-y-3 text-sm">
                <div className="flex items-center gap-2 text-emerald-300"><CheckCircle2 className="h-4 w-4" /> Scan {result.status.toLowerCase()}</div>
                <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-slate-300">
                  <dt className="text-slate-500">Files analysed</dt><dd>{result.files_scanned}</dd>
                  <dt className="text-slate-500">Findings</dt><dd>{result.findings_count}</dd>
                  <dt className="text-slate-500">Severity</dt>
                  <dd className="flex flex-wrap gap-2">
                    {(["CRITICAL", "HIGH", "MEDIUM", "LOW"] as const).filter((k) => result.severity_counts[k]).map((k) => (
                      <span key={k}><SeverityBadge severity={k} /> ×{result.severity_counts[k]}</span>
                    ))}
                    {result.findings_count === 0 && "—"}
                  </dd>
                </dl>
                {result.warnings.length > 0 && <ul className="list-disc pl-5 text-amber-300">{result.warnings.map((w) => <li key={w}>{w}</li>)}</ul>}
                <Link to={`/scans/${result.id}`} className="inline-block text-sky-400 hover:underline">View findings →</Link>
              </div>
            )}
          </Card>
        </div>
      )}
    </>
  );
}
