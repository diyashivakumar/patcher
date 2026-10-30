import { Bot, Database, ExternalLink, FlaskConical, Shield, TrendingUp } from "lucide-react";
import { Link } from "react-router-dom";
import { Card, Empty, ErrorBox, fmtDate, Loading, PageHeader, Pill, Stat } from "../components/ui";
import { useApi } from "../hooks/useApi";
import { api } from "../services/api";

export function Dashboard() {
  const summary = useApi(() => api.dashboard());
  const health = useApi(() => api.health());
  const ollama = useApi(() => api.ollamaStatus());
  const s = summary.data;

  const dbOk = health.data?.database === "ok" || health.data?.database === "mock";

  return (
    <>
      <PageHeader
        title="Security Overview"
        subtitle="Live metrics pulled directly from the backend database — nothing estimated."
        actions={
          <Link
            to="/replay"
            className="inline-flex items-center gap-2 rounded-xl bg-gradient-to-r from-sky-500 to-sky-400 px-4 py-2 text-sm font-semibold text-slate-950 shadow-lg shadow-sky-500/20 transition-all hover:from-sky-400 hover:to-sky-300 hover:shadow-sky-400/30 active:scale-95"
          >
            <FlaskConical className="h-4 w-4" />
            Attack Replay Lab
          </Link>
        }
      />

      {/* Status pills */}
      <div className="mb-7 flex flex-wrap gap-2 animate-fade-in">
        <Pill
          className={dbOk
            ? "bg-emerald-500/10 text-emerald-300 ring-emerald-500/30"
            : "bg-rose-500/10 text-rose-300 ring-rose-500/30"}
        >
          <Database className="h-3.5 w-3.5" />
          Database: {health.error ? "unreachable" : health.data?.database ?? "…"}
        </Pill>
        <Pill
          className={ollama.data?.model_installed
            ? "bg-emerald-500/10 text-emerald-300 ring-emerald-500/30"
            : "bg-slate-700/30 text-slate-400 ring-slate-600"}
        >
          <Bot className="h-3.5 w-3.5" />
          AI: {ollama.data
            ? ollama.data.model_installed
              ? `ready · ${ollama.data.model}`
              : "offline (optional)"
            : "…"}
        </Pill>
      </div>

      <ErrorBox error={summary.error} onRetry={summary.reload} />
      {summary.loading && !s && <Loading />}

      {s && (
        <>
          {/* Stats grid */}
          <div className="grid grid-cols-2 gap-4 lg:grid-cols-4 stagger">
            <Stat label="Projects" value={s.total_projects} />
            <Stat label="Scans" value={s.total_scans} />
            <Stat label="Findings" value={s.total_findings} />
            <Stat
              label="Critical / High"
              value={`${s.findings_by_severity.CRITICAL} / ${s.findings_by_severity.HIGH}`}
              accent="text-rose-300"
            />
            <Stat label="Patches generated" value={s.patches_generated} />
            <Stat
              label="Patches verified"
              value={s.patches_verified}
              accent="text-emerald-300"
              hint="Currently in VERIFIED state"
            />
            <Stat
              label="Patches rejected"
              value={s.patches_rejected}
              accent="text-rose-300"
              hint="Currently in REJECTED state"
            />
            <Stat
              label="Proof-of-Fix runs"
              value={`${s.verification_runs_by_verdict.VERIFIED} ✓ · ${s.verification_runs_by_verdict.FAILED} ✗`}
              hint={`${s.verification_runs_by_verdict.PARTIALLY_VERIFIED} partially verified`}
            />
          </div>

          {/* Recent scans */}
          <Card
            title={
              <span className="inline-flex items-center gap-2">
                <TrendingUp className="h-4 w-4 text-sky-400" />
                Recent scan activity
              </span>
            }
            actions={
              <Link to="/projects" className="inline-flex items-center gap-1.5 rounded-lg px-2.5 py-1.5 text-xs font-medium text-sky-400 transition hover:bg-sky-500/10">
                All projects <ExternalLink className="h-3 w-3" />
              </Link>
            }
            className="mt-6 animate-fade-in"
          >
            {s.recent_scans.length === 0 ? (
              <Empty>
                No scans yet.{" "}
                <Link className="text-sky-400 hover:underline" to="/projects">
                  Create a project
                </Link>{" "}
                to begin.
              </Empty>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full min-w-[520px] text-left text-sm">
                  <thead>
                    <tr className="text-[11px] font-semibold uppercase tracking-widest text-slate-500">
                      <th className="pb-3">Project</th>
                      <th className="pb-3">Status</th>
                      <th className="pb-3">Findings</th>
                      <th className="pb-3">Started</th>
                      <th className="pb-3" />
                    </tr>
                  </thead>
                  <tbody>
                    {s.recent_scans.map((scan) => (
                      <tr key={scan.id} className="border-t border-slate-800/60 group">
                        <td className="py-3 font-medium text-slate-200">{scan.project_name}</td>
                        <td className="py-3">
                          <span className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-xs font-semibold ring-1 ring-inset ${
                            scan.status === "completed"
                              ? "bg-emerald-500/10 text-emerald-300 ring-emerald-500/30"
                              : scan.status === "failed"
                              ? "bg-rose-500/10 text-rose-300 ring-rose-500/30"
                              : "bg-sky-500/10 text-sky-300 ring-sky-500/30"
                          }`}>
                            {scan.status}
                          </span>
                        </td>
                        <td className="py-3 tabular-nums text-slate-300">{scan.findings_count}</td>
                        <td className="py-3 text-slate-400 tabular-nums text-xs">{fmtDate(scan.started_at)}</td>
                        <td className="py-3 text-right">
                          <Link
                            className="inline-flex items-center gap-1 rounded-lg px-2.5 py-1 text-xs font-medium text-sky-400 transition hover:bg-sky-500/10"
                            to={`/scans/${scan.id}`}
                          >
                            View findings <ExternalLink className="h-3 w-3" />
                          </Link>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </Card>

          {/* Quick-action banner */}
          <div className="mt-6 flex flex-col gap-3 rounded-2xl border border-sky-500/20 bg-gradient-to-r from-sky-500/[0.07] to-indigo-500/[0.05] p-5 sm:flex-row sm:items-center animate-fade-in">
            <Shield className="h-8 w-8 shrink-0 text-sky-400" />
            <div className="flex-1">
              <p className="font-semibold text-white text-sm">Ready to test your code?</p>
              <p className="mt-0.5 text-xs text-slate-400">
                Create a project, run a scan, generate a patch, then prove it works with the Attack Replay Lab.
              </p>
            </div>
            <Link
              to="/projects"
              className="shrink-0 inline-flex items-center gap-2 rounded-xl border border-sky-500/40 bg-sky-500/10 px-4 py-2 text-sm font-semibold text-sky-300 transition hover:bg-sky-500/20"
            >
              New project →
            </Link>
          </div>
        </>
      )}
    </>
  );
}
