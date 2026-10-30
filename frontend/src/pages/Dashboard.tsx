import { Bot, Database, FlaskConical } from "lucide-react";
import { Link } from "react-router-dom";
import { Card, Empty, ErrorBox, fmtDate, Loading, PageHeader, Pill, Stat } from "../components/ui";
import { useApi } from "../hooks/useApi";
import { api } from "../services/api";

export function Dashboard() {
  const summary = useApi(() => api.dashboard());
  const health = useApi(() => api.health());
  const ollama = useApi(() => api.ollamaStatus());
  const s = summary.data;

  return (
    <>
      <PageHeader
        title="Security overview"
        subtitle="Every number below comes from the backend database. Nothing is estimated."
        actions={<Link to="/replay" className="inline-flex items-center gap-2 rounded-lg bg-sky-500 px-3.5 py-2 text-sm font-medium text-slate-950 hover:bg-sky-400"><FlaskConical className="h-4 w-4" />Attack Replay Lab</Link>}
      />
      <div className="mb-6 flex flex-wrap gap-2 text-xs">
        <Pill className={health.data?.database === "ok" || health.data?.database === "mock"
          ? "bg-emerald-500/10 text-emerald-300 ring-emerald-500/30" : "bg-rose-500/10 text-rose-300 ring-rose-500/30"}>
          <Database className="h-3.5 w-3.5" /> Database: {health.error ? "unreachable" : health.data?.database ?? "…"}
        </Pill>
        <Pill className={ollama.data?.model_installed ? "bg-emerald-500/10 text-emerald-300 ring-emerald-500/30" : "bg-slate-700/30 text-slate-400 ring-slate-600"}>
          <Bot className="h-3.5 w-3.5" /> AI assistant: {ollama.data ? (ollama.data.model_installed ? `ready (${ollama.data.model})` : "offline — optional") : "…"}
        </Pill>
      </div>

      <ErrorBox error={summary.error} onRetry={summary.reload} />
      {summary.loading && !s && <Loading />}
      {s && (
        <>
          <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
            <Stat label="Projects" value={s.total_projects} />
            <Stat label="Scans" value={s.total_scans} />
            <Stat label="Findings" value={s.total_findings} />
            <Stat label="Critical / High" value={`${s.findings_by_severity.CRITICAL} / ${s.findings_by_severity.HIGH}`} accent="text-rose-300" />
            <Stat label="Patches generated" value={s.patches_generated} />
            <Stat label="Patches verified" value={s.patches_verified} accent="text-emerald-300" hint="Currently in VERIFIED state" />
            <Stat label="Patches rejected" value={s.patches_rejected} accent="text-rose-300" hint="Currently in REJECTED state" />
            <Stat label="Proof-of-Fix runs" value={`${s.verification_runs_by_verdict.VERIFIED} ✓ · ${s.verification_runs_by_verdict.FAILED} ✗`}
              hint={`${s.verification_runs_by_verdict.PARTIALLY_VERIFIED} partially verified`} />
          </div>
          <Card title="Recent scan activity" className="mt-6">
            {s.recent_scans.length === 0 ? (
              <Empty>No scans yet. <Link className="text-sky-400 hover:underline" to="/projects">Create a project</Link> to begin.</Empty>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full min-w-[520px] text-left text-sm">
                  <thead className="text-xs uppercase tracking-wide text-slate-500">
                    <tr><th className="pb-2">Project</th><th className="pb-2">Status</th><th className="pb-2">Findings</th><th className="pb-2">Started</th><th /></tr>
                  </thead>
                  <tbody>
                    {s.recent_scans.map((scan) => (
                      <tr key={scan.id} className="border-t border-slate-800">
                        <td className="py-2.5">{scan.project_name}</td>
                        <td className="py-2.5 text-slate-400">{scan.status}</td>
                        <td className="py-2.5 tabular-nums">{scan.findings_count}</td>
                        <td className="py-2.5 text-slate-400">{fmtDate(scan.started_at)}</td>
                        <td className="py-2.5 text-right"><Link className="text-sky-400 hover:underline" to={`/scans/${scan.id}`}>View findings</Link></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </Card>
        </>
      )}
    </>
  );
}
