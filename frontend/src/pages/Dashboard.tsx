import {
  ArrowRight,
  Bot,
  Database,
  FlaskConical,
  FolderPlus,
  ScanSearch,
  ShieldCheck,
  Zap,
} from "lucide-react";
import { Link } from "react-router-dom";
import {
  Button,
  Card,
  Empty,
  ErrorBox,
  fmtDate,
  Loading,
  PageHeader,
  Pill,
  Stat,
  strategyLabel,
  VerdictBadge,
  vulnLabel,
} from "../components/ui";
import { useApi } from "../hooks/useApi";
import { api } from "../services/api";

export function Dashboard() {
  const summary = useApi(() => api.dashboard());
  const projects = useApi(() => api.listProjects());
  const reports = useApi(() => api.listReports());
  const health = useApi(() => api.health());
  const ollama = useApi(() => api.ollamaStatus());
  const s = summary.data;

  const reloadAll = () => {
    for (const q of [summary, projects, reports, health, ollama]) void q.reload();
  };

  const latest = projects.data?.flatMap((p) => (p.latest_scan ? [p.latest_scan] : [])) ?? [];
  const openFindings = latest.reduce((n, sc) => n + sc.findings_count, 0);
  const openCritHigh = latest.reduce(
    (n, sc) => n + (sc.severity_counts.CRITICAL ?? 0) + (sc.severity_counts.HIGH ?? 0),
    0
  );
  const recentRuns = reports.data?.slice(0, 5) ?? [];

  return (
    <div className="space-y-6">
      <PageHeader
        title="Security Overview"
        subtitle="Empirical proof-of-fix verification and live vulnerability tracking."
        actions={
          <div className="flex flex-wrap items-center gap-2">
            <Link to="/projects">
              <Button variant="secondary" className="gap-2">
                <FolderPlus className="h-4 w-4 text-slate-400" />
                New Project
              </Button>
            </Link>
            <Link to="/scanner">
              <Button variant="secondary" className="gap-2">
                <ScanSearch className="h-4 w-4 text-slate-400" />
                Scan Code
              </Button>
            </Link>
            <Link to="/replay">
              <Button variant="primary" className="gap-2">
                <FlaskConical className="h-4 w-4" />
                Attack Replay Lab
              </Button>
            </Link>
          </div>
        }
      />

      {/* System Status Strip */}
      <div className="flex flex-wrap items-center gap-3 rounded-xl border border-slate-800/80 bg-[#10141d]/60 px-4 py-2.5 text-xs text-slate-400">
        <span className="font-semibold text-slate-300">Engine Telemetry:</span>
        <div className="flex items-center gap-1.5">
          <Database className="h-3.5 w-3.5 text-slate-500" />
          <span>Storage:</span>
          <span className="font-medium text-slate-200">
            {health.error ? "Unreachable" : health.data?.database ?? "Checking..."}
          </span>
        </div>
        <span className="text-slate-700">·</span>
        <div className="flex items-center gap-1.5">
          <ShieldCheck className="h-3.5 w-3.5 text-emerald-400" />
          <span>Proof Engine:</span>
          <span className="font-medium text-emerald-300">Active (SQLi · IDOR)</span>
        </div>
        <span className="text-slate-700">·</span>
        <div className="flex items-center gap-1.5">
          <Bot className="h-3.5 w-3.5 text-slate-500" />
          <span>AI Explanations:</span>
          <span className="font-medium text-slate-300">
            {ollama.data?.model_installed ? `Ready (${ollama.data.model})` : "Local (Optional)"}
          </span>
        </div>
      </div>

      <ErrorBox error={summary.error ?? projects.error} onRetry={reloadAll} />
      {(summary.loading || projects.loading) && !s && <Loading />}

      {s && projects.data && (
        <>
          {/* Main Key Metrics */}
          <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
            <Stat
              label="Projects Tracked"
              value={s.total_projects}
              hint="Active test targets"
            />
            <Stat
              label="Open Findings"
              value={openFindings}
              accent={openFindings > 0 ? "text-amber-400" : "text-emerald-400"}
              hint={`${openCritHigh} Critical or High`}
            />
            <Stat
              label="Patches Verified"
              value={s.patches_verified}
              accent="text-emerald-400"
              hint={`${s.patches_generated} total generated`}
            />
            <Stat
              label="Proof Verdicts"
              value={`${s.verification_runs_by_verdict.VERIFIED} passed`}
              accent="text-white"
              hint={`${s.verification_runs_by_verdict.FAILED} failed checks`}
            />
          </div>

          {/* Quick Workflow Guide Banner */}
          <div className="rounded-xl border border-slate-800/80 bg-gradient-to-r from-sky-950/20 via-[#10141d] to-[#10141d] p-5">
            <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
              <div>
                <div className="flex items-center gap-2 text-sm font-semibold text-white">
                  <Zap className="h-4 w-4 text-sky-400" />
                  How PatchProof Works
                </div>
                <p className="mt-1 text-xs text-slate-400 max-w-2xl leading-relaxed">
                  We don't just rely on static scanner alerts. When a bug is identified, our engine reproduces the exploit on an isolated throwaway sandbox, writes a targeted defensive patch, and validates that real-world attackers are blocked while legitimate users retain full access.
                </p>
              </div>
              <Link to="/replay" className="shrink-0">
                <Button variant="secondary" className="w-full sm:w-auto gap-2 text-xs">
                  Launch Attack Replay <ArrowRight className="h-3.5 w-3.5 text-sky-400" />
                </Button>
              </Link>
            </div>
          </div>

          {/* Activity Tables */}
          <div className="grid gap-6 xl:grid-cols-2">
            {/* Recent Scans */}
            <Card
              title="Recent Code Scans"
              subtitle="Python AST static vulnerability analysis"
              actions={
                <Link className="text-xs text-sky-400 hover:text-sky-300 font-medium inline-flex items-center gap-1" to="/findings">
                  All Findings <ArrowRight className="h-3 w-3" />
                </Link>
              }
            >
              {s.recent_scans.length === 0 ? (
                <Empty>
                  No scans run yet. <Link className="text-sky-400 hover:underline" to="/projects">Select a project</Link> to run your first scan.
                </Empty>
              ) : (
                <div className="divide-y divide-slate-800/60">
                  {s.recent_scans.map((scan) => (
                    <div key={scan.id} className="flex items-center justify-between gap-3 py-3">
                      <div className="min-w-0">
                        <Link
                          to={`/scans/${scan.id}`}
                          className="font-medium text-xs sm:text-sm text-slate-200 hover:text-sky-400 transition truncate block"
                        >
                          {scan.project_name}
                        </Link>
                        <div className="text-[11px] text-slate-500 mt-0.5">
                          {fmtDate(scan.started_at)}
                        </div>
                      </div>
                      <div className="flex items-center gap-2 shrink-0">
                        <span className="rounded-md border border-slate-700/60 bg-slate-800/60 px-2 py-0.5 text-xs text-slate-300 font-mono">
                          {scan.findings_count} {scan.findings_count === 1 ? "issue" : "issues"}
                        </span>
                        <Link
                          to={`/scans/${scan.id}`}
                          className="text-xs text-slate-400 hover:text-slate-200 p-1"
                        >
                          <ArrowRight className="h-3.5 w-3.5" />
                        </Link>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </Card>

            {/* Recent Verification Proofs */}
            <Card
              title="Proof-of-Fix Results"
              subtitle="Deterministic replay & regression test verdicts"
              actions={
                <Link className="text-xs text-sky-400 hover:text-sky-300 font-medium inline-flex items-center gap-1" to="/reports">
                  All Reports <ArrowRight className="h-3 w-3" />
                </Link>
              }
            >
              <ErrorBox error={reports.error} onRetry={reloadAll} />
              {reports.data && recentRuns.length === 0 && (
                <Empty>
                  No verification runs recorded yet. Test an exploit in the{" "}
                  <Link className="text-sky-400 hover:underline" to="/replay">
                    Attack Replay Lab
                  </Link>.
                </Empty>
              )}
              {recentRuns.length > 0 && (
                <div className="divide-y divide-slate-800/60">
                  {recentRuns.map((r) => (
                    <div key={r.report_id} className="flex items-center justify-between gap-3 py-3">
                      <div className="min-w-0">
                        <Link
                          className="text-xs sm:text-sm font-medium text-slate-200 hover:text-sky-400 transition block truncate"
                          to={`/verification/${r.report_id}`}
                        >
                          {vulnLabel(r.scenario)}
                        </Link>
                        <div className="text-[11px] text-slate-500 mt-0.5 flex items-center gap-2">
                          <span>{fmtDate(r.created_at)}</span>
                          <span>·</span>
                          <span>{r.kind === "proof_of_fix" ? strategyLabel(r.patch_strategy ?? "") : "Baseline"}</span>
                        </div>
                      </div>
                      <div className="shrink-0">
                        {r.kind === "proof_of_fix" ? (
                          <VerdictBadge verdict={r.verdict} />
                        ) : (
                          <Pill
                            className={
                              r.original_vulnerability_reproduced
                                ? "border-rose-500/30 bg-rose-500/10 text-rose-300"
                                : "border-slate-700 bg-slate-800/60 text-slate-400"
                            }
                          >
                            {r.original_vulnerability_reproduced ? "Reproduced" : "Not Exploited"}
                          </Pill>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </Card>
          </div>
        </>
      )}
    </div>
  );
}
