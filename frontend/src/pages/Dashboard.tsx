import {
  ArrowRight,
  ArrowUpRight,
  CheckCheck,
  Crosshair,
  FlaskConical,
  FolderPlus,
  ScanSearch,
  ShieldCheck,
} from "lucide-react";
import { Link } from "react-router-dom";
import { AttackTopology, SeverityChart } from "../components/SecurityVisuals";
import {
  Button,
  Card,
  Empty,
  ErrorBox,
  fmtDate,
  Loading,
  Pill,
  VerdictBadge,
  vulnLabel,
} from "../components/ui";
import { useApi } from "../hooks/useApi";
import { api } from "../services/api";

export function Dashboard() {
  const summary = useApi(() => api.dashboard());
  const projects = useApi(() => api.listProjects());
  const reports = useApi(() => api.listReports());
  const findings = useApi(async () => {
    const list = await api.listProjects();
    return (
      await Promise.all(
        list
          .filter((p) => p.latest_scan)
          .map((p) => api.getScanFindings(p.latest_scan!.id)),
      )
    ).flat();
  });
  const runs = useApi(async () => {
    const list = await api.listRuns();
    const latest = list
      .filter((r) => r.kind === "proof_of_fix" && r.status === "COMPLETED")
      .sort((a, b) => Date.parse(b.created_at) - Date.parse(a.created_at))[0];
    return latest ? api.getRun(latest.id) : null;
  });
  const s = summary.data;
  const latestScans =
    projects.data?.flatMap((p) => (p.latest_scan ? [p.latest_scan] : [])) ?? [];
  const openFindings = latestScans.reduce((n, sc) => n + sc.findings_count, 0);
  const criticalHigh = latestScans.reduce(
    (n, sc) =>
      n + (sc.severity_counts.CRITICAL ?? 0) + (sc.severity_counts.HIGH ?? 0),
    0,
  );
  const recent = [...(reports.data ?? [])]
    .sort((a, b) => Date.parse(b.created_at) - Date.parse(a.created_at))
    .slice(0, 5);
  const verdicts = s?.verification_runs_by_verdict;
  const runCount = verdicts
    ? Object.values(verdicts).reduce((n, v) => n + v, 0)
    : 0;
  const regression = runs.data?.phase_summaries.after_patch?.regression_tests;
  const reload = () => {
    for (const q of [summary, projects, reports, findings, runs])
      void q.reload();
  };
  return (
    <div className="space-y-6">
      <section className="command-hero">
        <div>
          <div className="eyebrow">
            <span className="hero-crosshair">✧</span> SECURITY COMMAND CENTRE
          </div>
          <h1>
            Every fix.
            <br />
            <span>Put to the proof.</span>
          </h1>
          <p>
            Your vulnerability investigations, connected.
            <br className="hidden sm:block" /> Find the flaw. Challenge the fix.
            Prove it with evidence.
          </p>
          <div className="hero-actions">
            <Link to="/projects">
              <Button>
                <FolderPlus size={15} />
                New Project
              </Button>
            </Link>
            <Link to="/scanner">
              <Button variant="secondary">
                <ScanSearch size={15} />
                Start Scan
              </Button>
            </Link>
            <Link className="hero-lab-link" to="/replay">
              Attack Replay Lab <ArrowUpRight size={15} />
            </Link>
          </div>
        </div>
        <div className="hero-emblem" aria-hidden="true">
          <div className="emblem-orbit orbit-one" />
          <div className="emblem-orbit orbit-two" />
          <div className="emblem-orbit orbit-three" />
          <ShieldCheck size={76} strokeWidth={0.8} />
          <span>DEFENSE THROUGH EVIDENCE</span>
          <i className="orbit-point point-one" />
          <i className="orbit-point point-two" />
        </div>
        <span className="hero-coordinate" aria-hidden="true">
          PP / CONTROL PLANE — 001
        </span>
      </section>
      <ErrorBox error={summary.error ?? projects.error} onRetry={reload} />
      {(summary.loading || projects.loading) && !s && (
        <Loading label="Loading investigation telemetry…" />
      )}
      {s && projects.data && (
        <>
          <section className="overview-bento" aria-label="Security overview">
            <div className="overview-lead">
              <div className="eyebrow">
                <Crosshair size={13} /> ATTENTION REQUIRED
              </div>
              <div className="overview-number">
                {openFindings.toString().padStart(2, "0")}
                <span>
                  open
                  <br />
                  vulnerabilities
                </span>
              </div>
              <Link to="/findings">
                <span>{criticalHigh} critical / high severity</span>
                <ArrowUpRight size={16} />
              </Link>
            </div>
            <div className="overview-metric">
              <FolderPlus size={18} />
              <strong>{s.total_projects}</strong>
              <span>Projects</span>
              <small>Investigation targets</small>
            </div>
            <div className="overview-metric">
              <ScanSearch size={18} />
              <strong>{s.total_scans}</strong>
              <span>Total scans</span>
              <small>Static code analysis</small>
            </div>
            <div className="overview-metric">
              <ShieldCheck size={18} className="text-emerald-400" />
              <strong className="text-emerald-400">{s.patches_verified}</strong>
              <span>Verified patches</span>
              <small>
                {s.patches_generated} generated · {s.patches_rejected} rejected
              </small>
            </div>
            <div className="overview-metric">
              <FlaskConical size={18} className="text-brand-violet" />
              <strong>{runCount}</strong>
              <span>Proof-of-Fix runs</span>
              <small>
                <span className="text-rose-300">
                  {verdicts?.FAILED ?? 0} failed
                </span>{" "}
                · {verdicts?.PARTIALLY_VERIFIED ?? 0} partial
              </small>
            </div>
          </section>
          <div className="command-dashboard-grid">
            <Card
              className="topology-panel"
              title={
                <span className="flex items-center gap-2">
                  <Crosshair size={16} className="text-sky-400" />
                  Investigation topology
                </span>
              }
              subtitle="From vulnerable code to verified defense"
              actions={
                <Link to="/projects" className="panel-link">
                  Explore projects <ArrowUpRight size={13} />
                </Link>
              }
            >
              <ErrorBox
                error={findings.error ?? reports.error}
                onRetry={reload}
              />
              {findings.loading || reports.loading ? (
                <Loading />
              ) : (
                findings.data &&
                reports.data && (
                  <AttackTopology
                    projects={projects.data}
                    findings={findings.data}
                    reports={reports.data}
                  />
                )
              )}
            </Card>
            <Card
              title="Threat distribution"
              subtitle="All recorded scan findings"
            >
              <SeverityChart counts={s.findings_by_severity} />
              <div className="verification-summary">
                <div className="flex justify-between gap-2 text-xs">
                  <span className="flex items-center gap-2">
                    <CheckCheck size={14} />
                    Proof verdicts
                  </span>
                  <b>
                    {verdicts?.VERIFIED ?? 0} verified / {runCount}
                  </b>
                </div>
                <div
                  className="verdict-bar"
                  role="img"
                  aria-label={`${verdicts?.VERIFIED ?? 0} verified, ${verdicts?.FAILED ?? 0} failed, ${verdicts?.PARTIALLY_VERIFIED ?? 0} partial`}
                >
                  {(["VERIFIED", "PARTIALLY_VERIFIED", "FAILED"] as const).map(
                    (v) => (
                      <span
                        key={v}
                        style={{
                          width: `${runCount ? ((verdicts?.[v] ?? 0) / runCount) * 100 : 0}%`,
                          background:
                            v === "VERIFIED"
                              ? "#35E6A1"
                              : v === "FAILED"
                                ? "#FF5576"
                                : "#FFC66D",
                        }}
                      />
                    ),
                  )}
                </div>
                <p>
                  {runCount
                    ? "Deterministic verdicts from executed tests."
                    : "No Proof-of-Fix verdicts recorded yet."}
                </p>
              </div>
            </Card>
          </div>
          <div className="grid gap-6 xl:grid-cols-[1.4fr_1fr]">
            <Card
              title="Investigation activity"
              subtitle="Most recent executed verification runs"
              actions={
                <Link to="/reports" className="panel-link">
                  All evidence <ArrowRight size={13} />
                </Link>
              }
            >
              <ErrorBox error={reports.error} onRetry={reports.reload} />
              {!recent.length && (
                <Empty>
                  No investigations yet.{" "}
                  <Link className="text-sky-400" to="/replay">
                    Open the Replay Lab
                  </Link>{" "}
                  to begin.
                </Empty>
              )}
              <div className="investigation-feed">
                {recent.map((r) => (
                  <Link
                    key={r.report_id}
                    to={`/verification/${r.report_id}`}
                    className="investigation-entry"
                  >
                    <span
                      className={`feed-marker ${r.verdict === "VERIFIED" ? "verified" : ""}`}
                    >
                      <FlaskConical size={16} />
                    </span>
                    <div className="min-w-0 flex-1">
                      <strong>{vulnLabel(r.scenario)}</strong>
                      <p>
                        {projects.data?.find((p) => p.id === r.project_id)
                          ?.name ?? r.project_id.slice(0, 8)}{" "}
                        ·{" "}
                        {r.kind === "baseline"
                          ? "Baseline replay"
                          : "Proof-of-Fix"}
                      </p>
                      <time dateTime={r.created_at}>
                        {fmtDate(r.created_at)}
                      </time>
                    </div>
                    <div className="text-right">
                      <VerdictBadge verdict={r.verdict} />
                      <span className="mt-1 block text-[10px] text-slate-500">
                        Severity: not in report summary
                      </span>
                    </div>
                    <ArrowUpRight
                      size={15}
                      className="shrink-0 text-slate-500"
                    />
                  </Link>
                ))}
              </div>
            </Card>
            <div className="space-y-6">
              <Card
                title="Latest regression evidence"
                subtitle="Most recent completed Proof-of-Fix run"
              >
                <ErrorBox error={runs.error} onRetry={runs.reload} />
                {runs.loading ? (
                  <Loading />
                ) : regression && runs.data ? (
                  <>
                    <div className="regression-value">
                      <strong>
                        {regression.passed}
                        <span> / {regression.total}</span>
                      </strong>
                      <span>tests passed</span>
                    </div>
                    <div className="mt-3 flex flex-wrap gap-2">
                      <Pill className="border-rose-500/20 text-rose-300">
                        {regression.failed} failed
                      </Pill>
                      <Pill className="border-amber-500/20 text-amber-300">
                        {regression.errors} errors
                      </Pill>
                    </div>
                    <Link
                      className="panel-link mt-4"
                      to={`/verification/${runs.data.id}`}
                    >
                      Inspect executed tests <ArrowRight size={13} />
                    </Link>
                  </>
                ) : (
                  !runs.error && (
                    <p className="text-sm text-slate-400">
                      No after-patch regression evidence recorded yet.
                    </p>
                  )
                )}
              </Card>
              <Card title="Exposure & bypass evidence">
                <div className="evidence-unavailable">
                  <Crosshair size={22} />
                  <div>
                    <strong>Awaiting supported evidence</strong>
                    <p>
                      The current API does not expose variation bypasses or
                      record-level exposure summaries. Investigate the available
                      replay evidence.
                    </p>
                    <Link to="/replay" className="panel-link">
                      Open Attack Replay Lab <ArrowUpRight size={13} />
                    </Link>
                  </div>
                </div>
              </Card>
            </div>
          </div>
          <Card
            title="Latest code scans"
            subtitle="Scanner status reported by the backend"
          >
            <div className="scan-feed">
              {s.recent_scans.length === 0 && (
                <Empty>
                  No scans yet.{" "}
                  <Link to="/scanner" className="text-sky-400">
                    Start an investigation.
                  </Link>
                </Empty>
              )}
              {s.recent_scans.map((scan) => (
                <Link key={scan.id} to={`/scans/${scan.id}`}>
                  <ScanSearch size={18} className="text-sky-400" />
                  <div>
                    <strong>{scan.project_name}</strong>
                    <small>{fmtDate(scan.started_at)}</small>
                  </div>
                  <Pill className="border-command-border text-slate-300">
                    {scan.status}
                  </Pill>
                  <span className="text-xs text-slate-400">
                    {scan.findings_count} findings
                  </span>
                  <ArrowUpRight size={15} />
                </Link>
              ))}
            </div>
          </Card>
        </>
      )}
    </div>
  );
}
