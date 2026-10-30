import { Bot, Database, FlaskConical, FolderPlus, ScanSearch } from "lucide-react";
import { Link } from "react-router-dom";
import { Card, Empty, ErrorBox, fmtDate, Loading, PageHeader, Pill, Stat, strategyLabel, VerdictBadge, vulnLabel } from "../components/ui";
import { useApi } from "../hooks/useApi";
import { api } from "../services/api";

const action = "inline-flex items-center gap-2 rounded-lg px-3.5 py-2 text-sm font-medium";

export function Dashboard() {
  const summary = useApi(() => api.dashboard());
  const projects = useApi(() => api.listProjects());
  const reports = useApi(() => api.listReports());
  const health = useApi(() => api.health());
  const ollama = useApi(() => api.ollamaStatus());
  const s = summary.data;
  const reloadAll = () => { for (const q of [summary, projects, reports, health, ollama]) void q.reload(); };

  // "Open" = findings in each project's most recent scan (older scans are superseded by re-scans).
  const latest = projects.data?.flatMap((p) => (p.latest_scan ? [p.latest_scan] : [])) ?? [];
  const open = latest.reduce((n, sc) => n + sc.findings_count, 0);
  const openCritHigh = latest.reduce((n, sc) => n + (sc.severity_counts.CRITICAL ?? 0) + (sc.severity_counts.HIGH ?? 0), 0);
  const recentRuns = reports.data?.slice(0, 6) ?? [];

  return (
    <>
      <PageHeader
        title="Security overview"
        subtitle="Every number below comes from the backend database. Nothing is estimated."
        actions={<>
          <Link to="/projects" className={`${action} border border-slate-700 bg-slate-800 text-slate-100 hover:bg-slate-700`}><FolderPlus className="h-4 w-4" />New project</Link>
          <Link to="/scanner" className={`${action} border border-slate-700 bg-slate-800 text-slate-100 hover:bg-slate-700`}><ScanSearch className="h-4 w-4" />Start a scan</Link>
          <Link to="/replay" className={`${action} bg-sky-500 text-slate-950 hover:bg-sky-400`}><FlaskConical className="h-4 w-4" />Attack Replay Lab</Link>
        </>}
      />
      <div className="mb-6 flex flex-wrap gap-2 text-xs">
        <Pill className={health.data?.database === "ok" || health.data?.database === "mock"
          ? "bg-emerald-500/10 text-emerald-300 ring-emerald-500/30" : "bg-rose-500/10 text-rose-300 ring-rose-500/30"}>
          <Database className="h-3.5 w-3.5" /> Database: {health.error ? "unreachable" : health.data?.database ?? "checking…"}
        </Pill>
        <Pill className={ollama.data?.model_installed ? "bg-emerald-500/10 text-emerald-300 ring-emerald-500/30" : "bg-slate-700/30 text-slate-400 ring-slate-600"}>
          <Bot className="h-3.5 w-3.5" /> AI assistant: {ollama.error ? "unknown" : ollama.data ? (ollama.data.model_installed ? `ready (${ollama.data.model})` : "offline — optional") : "checking…"}
        </Pill>
      </div>

      <ErrorBox error={summary.error ?? projects.error} onRetry={reloadAll} />
      {(summary.loading || projects.loading) && !s && <Loading />}
      {s && projects.data && (
        <>
          <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
            <Stat label="Projects" value={s.total_projects} />
            <Stat label="Scans" value={s.total_scans} />
            <Stat label="Open findings" value={open} hint="In each project's latest scan" accent={open ? "text-rose-300" : undefined} />
            <Stat label="Open critical / high" value={openCritHigh} accent={openCritHigh ? "text-rose-300" : undefined} />
            <Stat label="Patches generated" value={s.patches_generated} />
            <Stat label="Verified patches" value={s.patches_verified} accent="text-emerald-300" hint="Currently in VERIFIED state" />
            <Stat label="Rejected patches" value={s.patches_rejected} accent={s.patches_rejected ? "text-rose-300" : undefined} hint="Currently in REJECTED state" />
            <Stat label="Proof-of-Fix runs" value={`${s.verification_runs_by_verdict.VERIFIED} ✓ · ${s.verification_runs_by_verdict.FAILED} ✗`}
              hint={`${s.verification_runs_by_verdict.PARTIALLY_VERIFIED} partially verified`} />
          </div>

          <div className="mt-6 grid gap-4 xl:grid-cols-2">
            <Card title="Recent scan activity" actions={<Link className="text-xs text-sky-400 hover:underline" to="/findings">All findings →</Link>}>
              {s.recent_scans.length === 0 ? (
                <Empty>No scans yet. <Link className="text-sky-400 hover:underline" to="/projects">Create a project</Link>, then start a scan.</Empty>
              ) : (
                <ul className="divide-y divide-slate-800 text-sm">
                  {s.recent_scans.map((scan) => (
                    <li key={scan.id} className="flex items-center justify-between gap-3 py-2.5">
                      <div className="min-w-0">
                        <div className="truncate text-slate-200">{scan.project_name}</div>
                        <div className="text-xs text-slate-500">{fmtDate(scan.started_at)} · {scan.status}</div>
                      </div>
                      <Link className="shrink-0 text-sky-400 hover:underline" to={`/scans/${scan.id}`}>{scan.findings_count} finding(s)</Link>
                    </li>
                  ))}
                </ul>
              )}
            </Card>
            <Card title="Recent verification results" actions={<Link className="text-xs text-sky-400 hover:underline" to="/reports">All reports →</Link>}>
              <ErrorBox error={reports.error} onRetry={reloadAll} />
              {reports.data && recentRuns.length === 0 && (
                <Empty>No verification runs yet. Prove a fix in the <Link className="text-sky-400 hover:underline" to="/replay">Attack Replay Lab</Link>.</Empty>
              )}
              {recentRuns.length > 0 && (
                <ul className="divide-y divide-slate-800 text-sm">
                  {recentRuns.map((r) => (
                    <li key={r.report_id} className="flex items-center justify-between gap-3 py-2.5">
                      <div className="min-w-0">
                        <Link className="text-slate-200 hover:text-sky-300" to={`/verification/${r.report_id}`}>
                          {vulnLabel(r.scenario)} · {r.kind === "proof_of_fix" ? strategyLabel(r.patch_strategy ?? "") : "baseline replay"}
                        </Link>
                        <div className="text-xs text-slate-500">{fmtDate(r.created_at)}</div>
                      </div>
                      {r.kind === "proof_of_fix" ? <VerdictBadge verdict={r.verdict} /> : (
                        <Pill className={r.original_vulnerability_reproduced ? "bg-rose-500/15 text-rose-300 ring-rose-500/40" : "bg-slate-700/30 text-slate-300 ring-slate-600"}>
                          {r.original_vulnerability_reproduced ? "EXPLOIT REPRODUCED" : "NOT REPRODUCED"}
                        </Pill>
                      )}
                    </li>
                  ))}
                </ul>
              )}
            </Card>
          </div>
        </>
      )}
    </>
  );
}
