import { Activity, FlaskConical, FolderPlus, Radar, ScanSearch, ShieldCheck } from "lucide-react";
import { Link } from "react-router-dom";
import { Donut, NetworkTopology, TopoLegend, type TopoLink, type TopoNode } from "../components/Charts";
import { Card, cx, Empty, ErrorBox, fmtDate, Pill, SkeletonRows, SkeletonStats, Stat, strategyLabel, VerdictBadge, vulnLabel } from "../components/ui";
import { useApi } from "../hooks/useApi";
import { api } from "../services/api";
import type { DashboardSummary, ReportListItem } from "../types/api";

const rgb = (t: string) => `rgb(var(--${t}))`;

function buildTopology(s: DashboardSummary, runs: ReportListItem[]): { nodes: TopoNode[]; links: TopoLink[] } {
  const nodes: TopoNode[] = [{ id: "proj", label: "Student Portal", sub: "project", x: 12, y: 50, kind: "project", to: "/projects" }];
  const links: TopoLink[] = [];
  const sev = s.open_findings_by_severity ?? s.findings_by_severity;
  const sevRows = (["CRITICAL", "HIGH", "MEDIUM"] as const).filter((k) => (sev?.[k] ?? 0) > 0);
  sevRows.forEach((k, i) => {
    const id = `sev-${k}`;
    nodes.push({ id, label: k, sub: `${sev[k]} open`, x: 38, y: sevRows.length === 1 ? 50 : 18 + (64 / (sevRows.length - 1)) * i, kind: "breached", to: "/findings" });
    links.push({ from: "proj", to: id, state: "breached" });
  });
  const topRuns = runs.slice(0, 3);
  topRuns.forEach((r, i) => {
    const id = `run-${r.report_id}`;
    const kind = r.verdict === "VERIFIED" ? "verified" : r.kind === "proof_of_fix" ? "breached" : "patch";
    nodes.push({ id, label: r.verdict ?? "BASELINE", sub: strategyLabel(r.patch_strategy ?? r.scenario), x: 66, y: topRuns.length === 1 ? 50 : 18 + (64 / (topRuns.length - 1)) * i, kind, to: `/verification/${r.report_id}` });
    const srcSev = sevRows[i % Math.max(1, sevRows.length)];
    if (srcSev) links.push({ from: `sev-${srcSev}`, to: id, state: r.verdict === "VERIFIED" ? "verified" : "breached" });
  });
  const failed = topRuns.filter((r) => r.verdict === "FAILED");
  if (failed.length) {
    nodes.push({ id: "exposed", label: "Exposed", sub: "synthetic records", x: 90, y: 50, kind: "exposed", to: "/forensics" });
    failed.forEach((r) => links.push({ from: `run-${r.report_id}`, to: "exposed", state: "breached" }));
  }
  return { nodes, links };
}

const QUICK = "inline-flex items-center gap-2 rounded-lg px-3.5 py-2 text-sm font-medium transition";

export function Dashboard() {
  const summary = useApi(() => api.dashboard());
  const projects = useApi(() => api.listProjects());
  const reports = useApi(() => api.listReports());
  const health = useApi(() => api.health());
  const ollama = useApi(() => api.ollamaStatus());
  const s = summary.data;
  const reloadAll = () => { for (const q of [summary, projects, reports, health, ollama]) void q.reload(); };

  const latest = projects.data?.flatMap((p) => (p.latest_scan ? [p.latest_scan] : [])) ?? [];
  const open = s?.open_findings ?? latest.reduce((n, sc) => n + sc.findings_count, 0);
  const openCritHigh = s?.open_findings_by_severity
    ? s.open_findings_by_severity.CRITICAL + s.open_findings_by_severity.HIGH
    : latest.reduce((n, sc) => n + (sc.severity_counts.CRITICAL ?? 0) + (sc.severity_counts.HIGH ?? 0), 0);
  const recentRuns = reports.data?.slice(0, 6) ?? [];
  const sev = s?.open_findings_by_severity;
  const sevTrend = sev ? [sev.CRITICAL, sev.HIGH, sev.MEDIUM, sev.LOW] : undefined;
  const dbOk = health.data?.database === "ok" || health.data?.database === "mock";

  return (
    <div className="space-y-6">
      <section className="glass rise-in relative overflow-hidden rounded-2xl p-6 sm:p-8">
        <div className="pointer-events-none absolute -right-20 -top-24 h-72 w-72 rounded-full bg-brand/10 blur-3xl" />
        <div className="pointer-events-none absolute -bottom-28 right-32 h-72 w-72 rounded-full bg-violet/10 blur-3xl" />
        <div className="relative flex flex-wrap items-end justify-between gap-5">
          <div className="min-w-0">
            <div className="mb-2 inline-flex items-center gap-2 rounded-full border border-brand/30 bg-brand/10 px-3 py-1 text-[11px] font-semibold uppercase tracking-[0.18em] text-brand">
              <Radar className="h-3.5 w-3.5" /> Security Command Centre
            </div>
            <h1 className="text-3xl font-semibold tracking-display text-white text-glow-cyan sm:text-4xl">Find the Flaw. Challenge the Fix. Prove It.</h1>
            <p className="mt-2 max-w-2xl text-sm leading-relaxed text-slate-400">
              Live view of every project, vulnerability, exploit attempt and Proof-of-Fix verdict. Every number is real backend data — nothing is estimated.
            </p>
            <div className="mt-3 flex flex-wrap gap-2 text-[11px]">
              <Pill className={dbOk ? "border-verified/30 bg-verified/10 text-verified ring-0" : "border-breached/30 bg-breached/10 text-breached ring-0"}>
                <span className={cx("h-1.5 w-1.5 rounded-full", dbOk ? "bg-verified" : "bg-breached")} /> Database {health.error ? "offline" : health.data?.database ?? "…"}
              </Pill>
              <Pill className={ollama.data?.model_installed ? "border-verified/30 bg-verified/10 text-verified ring-0" : "border-line/20 bg-surface-2/40 text-slate-400 ring-0"}>
                <span className={cx("h-1.5 w-1.5 rounded-full", ollama.data?.model_installed ? "bg-verified" : "bg-slate-500")} /> AI assistant {ollama.data?.model_installed ? `ready (${ollama.data.model})` : "optional"}
              </Pill>
            </div>
          </div>
          <div className="flex flex-wrap gap-2">
            <Link to="/projects" className={cx(QUICK, "border border-line/20 bg-surface-2/50 text-slate-100 hover:border-brand/40")}><FolderPlus className="h-4 w-4" />New project</Link>
            <Link to="/scanner" className={cx(QUICK, "border border-line/20 bg-surface-2/50 text-slate-100 hover:border-brand/40")}><ScanSearch className="h-4 w-4" />Start scan</Link>
            <Link to="/replay" className={cx(QUICK, "bg-brand text-brand-ink shadow-[0_8px_24px_-8px_rgb(var(--brand)/0.7)] hover:brightness-110")}><FlaskConical className="h-4 w-4" />Attack Replay Lab</Link>
          </div>
        </div>
      </section>

      <ErrorBox error={summary.error ?? projects.error} onRetry={reloadAll} />
      {(summary.loading || projects.loading) && !s && <div className="space-y-6"><SkeletonStats n={7} /><SkeletonRows rows={5} /></div>}

      {s && projects.data && (
        <>
          <div className="grid grid-cols-2 gap-4 lg:grid-cols-4 xl:grid-cols-7">
            <Stat label="Projects" value={s.total_projects} />
            <Stat label="Scans" value={s.total_scans} />
            <Stat label="Open vulns" value={open} accent={open ? "text-breached" : undefined} trend={sevTrend} hint="Latest scans, excl. verified" />
            <Stat label="Critical / High" value={openCritHigh} accent={openCritHigh ? "text-breached" : undefined} />
            <Stat label="Verified" value={s.patches_verified} accent="text-verified" />
            <Stat label="Rejected" value={s.patches_rejected} accent={s.patches_rejected ? "text-breached" : undefined} />
            <Stat label="Proof-of-Fix" value={`${s.verification_runs_by_verdict.VERIFIED}✓ ${s.verification_runs_by_verdict.FAILED}✗`}
              trend={[s.verification_runs_by_verdict.VERIFIED, s.verification_runs_by_verdict.PARTIALLY_VERIFIED, s.verification_runs_by_verdict.FAILED]} />
          </div>

          <div className="grid gap-4 xl:grid-cols-[minmax(0,2fr)_minmax(0,1fr)]">
            <Card title={<span className="inline-flex items-center gap-2"><Radar className="h-4 w-4 text-brand" />Attack network topology</span>} actions={<TopoLegend />}>
              <NetworkTopology {...buildTopology(s, recentRuns)} />
              <p className="mt-2 text-[11px] text-slate-500">Projects → vulnerabilities → verification outcomes → exposed synthetic records. Click a node to investigate.</p>
            </Card>
            <div className="grid gap-4">
              <Card title="Severity distribution">
                <Donut centerTop={String(s.total_findings)} centerSub="total findings"
                  slices={[
                    { label: "Critical", value: s.findings_by_severity.CRITICAL, color: rgb("breached") },
                    { label: "High", value: s.findings_by_severity.HIGH, color: "rgb(255 150 90)" },
                    { label: "Medium", value: s.findings_by_severity.MEDIUM, color: rgb("blocked") },
                    { label: "Low", value: s.findings_by_severity.LOW, color: rgb("blue") },
                  ]} />
              </Card>
              <Card title="Verification outcomes">
                <Donut centerTop={String(Object.values(s.verification_runs_by_verdict).reduce((a, b) => a + b, 0))} centerSub="proof-of-fix runs"
                  slices={[
                    { label: "Verified", value: s.verification_runs_by_verdict.VERIFIED, color: rgb("verified") },
                    { label: "Partially", value: s.verification_runs_by_verdict.PARTIALLY_VERIFIED, color: rgb("blocked") },
                    { label: "Failed", value: s.verification_runs_by_verdict.FAILED, color: rgb("breached") },
                  ]} />
              </Card>
            </div>
          </div>

          <div className="grid gap-4 xl:grid-cols-2">
            <Card title={<span className="inline-flex items-center gap-2"><ShieldCheck className="h-4 w-4 text-brand" />Recent verification results</span>}
              actions={<Link className="text-xs text-brand hover:underline" to="/reports">All reports →</Link>}>
              <ErrorBox error={reports.error} onRetry={reloadAll} />
              {reports.data && recentRuns.length === 0 && (
                <Empty>No verification runs yet. Prove a fix in the <Link className="text-brand hover:underline" to="/replay">Attack Replay Lab</Link>.</Empty>
              )}
              {recentRuns.length > 0 && (
                <ul className="divide-y divide-line/10 text-sm">
                  {recentRuns.map((r) => (
                    <li key={r.report_id} className="flex items-center justify-between gap-3 py-2.5">
                      <div className="min-w-0">
                        <Link className="text-slate-200 transition-colors hover:text-brand" to={`/verification/${r.report_id}`}>
                          {vulnLabel(r.scenario)} · {r.kind === "proof_of_fix" ? strategyLabel(r.patch_strategy ?? "") : "baseline replay"}
                        </Link>
                        <div className="text-xs text-slate-500">{fmtDate(r.created_at)}</div>
                      </div>
                      {r.kind === "proof_of_fix" ? <VerdictBadge verdict={r.verdict} /> : (
                        <Pill className={r.original_vulnerability_reproduced ? "bg-breached/15 text-breached ring-breached/40" : "bg-slate-700/30 text-slate-300 ring-slate-600"}>
                          {r.original_vulnerability_reproduced ? "EXPLOIT REPRODUCED" : "NOT REPRODUCED"}
                        </Pill>
                      )}
                    </li>
                  ))}
                </ul>
              )}
            </Card>
            <Card title={<span className="inline-flex items-center gap-2"><Activity className="h-4 w-4 text-brand" />Recent scan activity</span>}
              actions={<Link className="text-xs text-brand hover:underline" to="/findings">All findings →</Link>}>
              {s.recent_scans.length === 0 ? (
                <Empty>No scans yet. <Link className="text-brand hover:underline" to="/projects">Create a project</Link>, then start a scan.</Empty>
              ) : (
                <ul className="divide-y divide-line/10 text-sm">
                  {s.recent_scans.map((scan) => (
                    <li key={scan.id} className="flex items-center justify-between gap-3 py-2.5">
                      <div className="min-w-0">
                        <div className="truncate text-slate-200">{scan.project_name}</div>
                        <div className="text-xs text-slate-500">{fmtDate(scan.started_at)} · {scan.status}</div>
                      </div>
                      <Link className="shrink-0 text-brand hover:underline" to={`/scans/${scan.id}`}>{scan.findings_count} finding(s)</Link>
                    </li>
                  ))}
                </ul>
              )}
            </Card>
          </div>
        </>
      )}
    </div>
  );
}
