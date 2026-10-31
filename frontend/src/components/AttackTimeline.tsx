import {
  Bug, CheckCircle2, ChevronDown, Circle, Clock, FileDiff, Gavel, Loader2, MinusCircle, Repeat, ScanSearch,
  ShieldAlert, ShieldCheck, ShieldX, UserCheck, Users, XCircle,
} from "lucide-react";
import { useEffect, useState, type ReactNode } from "react";
import { Link } from "react-router-dom";
import type { TestResult, Verdict, VerificationRunDetail } from "../types/api";
import { DiffView } from "./CodeBlock";
import { buildTimeline, type Stage, type StageKey, type StageStatus, type TimelineInput } from "./timelineModel";
import { cx, fmtDate, VerdictBadge, vulnLabel } from "./ui";

const STAGE_ICON: Record<StageKey, typeof Bug> = {
  reproduce: Bug, confirm: ScanSearch, approve: UserCheck, apply: FileDiff, replay: Repeat, regression: Users, verdict: Gavel,
};

// Colour rules: green passed · red failed · amber awaiting/partial · blue running · grey pending/skipped/blocked.
const STATUS: Record<StageStatus, { label: string; ring: string; text: string; chip: string; Icon: typeof Bug }> = {
  pending: { label: "Pending", ring: "border-slate-700 bg-slate-900", text: "text-slate-500", chip: "bg-slate-700/30 text-slate-400 ring-slate-600", Icon: Circle },
  running: { label: "Running", ring: "border-sky-500 bg-sky-500/15", text: "text-sky-300", chip: "bg-sky-500/15 text-sky-300 ring-sky-500/40", Icon: Loader2 },
  passed: { label: "Passed", ring: "border-emerald-500 bg-emerald-500/15", text: "text-emerald-300", chip: "bg-emerald-500/15 text-emerald-300 ring-emerald-500/40", Icon: CheckCircle2 },
  failed: { label: "Failed", ring: "border-rose-500 bg-rose-500/15", text: "text-rose-300", chip: "bg-rose-500/15 text-rose-300 ring-rose-500/40", Icon: XCircle },
  skipped: { label: "Skipped", ring: "border-slate-700 bg-slate-900", text: "text-slate-500", chip: "bg-slate-700/30 text-slate-400 ring-slate-600", Icon: MinusCircle },
  blocked: { label: "Blocked", ring: "border-slate-600 bg-slate-800", text: "text-slate-400", chip: "bg-slate-700/40 text-slate-300 ring-slate-500", Icon: MinusCircle },
  awaiting: { label: "Awaiting approval", ring: "border-amber-500 bg-amber-500/15", text: "text-amber-300", chip: "bg-amber-500/15 text-amber-300 ring-amber-500/40", Icon: Clock },
  partial: { label: "Partially verified", ring: "border-amber-500 bg-amber-500/15", text: "text-amber-300", chip: "bg-amber-500/15 text-amber-300 ring-amber-500/40", Icon: ShieldAlert },
};

const fmtMs = (ms?: number | null) => (ms == null ? null : ms < 1000 ? `${ms} ms` : `${(ms / 1000).toFixed(1)} s`);

function Chip({ status }: { status: StageStatus }) {
  const s = STATUS[status];
  return <span className={cx("rounded-full px-2 py-0.5 text-[11px] font-semibold ring-1 ring-inset", s.chip)}>{s.label}</span>;
}

function TestLine({ t, showExploit }: { t: TestResult; showExploit?: boolean }) {
  const ok = t.status === "passed";
  return (
    <li className="flex gap-2 py-1.5">
      {ok ? <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-emerald-400" /> : <XCircle className="mt-0.5 h-4 w-4 shrink-0 text-rose-400" />}
      <div className="min-w-0">
        <div className="text-slate-200">{t.name}</div>
        <div className="text-xs text-slate-500">
          expected {t.privilege_map?.expected ?? t.expected} · observed <span className={ok ? "text-slate-300" : "text-rose-300"}>{t.actual}</span>
          {showExploit && t.exploit_succeeded && <span className="ml-1 font-semibold text-rose-300">· exploit succeeded</span>}
        </div>
      </div>
    </li>
  );
}

function Compare({ rows, kind }: { rows: NonNullable<Stage["compare"]>; kind: "security" | "regression" }) {
  const cell = (t?: TestResult) => {
    if (!t) return <span className="text-slate-600">not run</span>;
    const ok = t.status === "passed";
    const label = kind === "security" ? (t.exploit_succeeded ? "Exploited" : ok ? "Blocked" : "Failed") : ok ? "Works" : "Broken";
    return <span className={cx("inline-flex items-center gap-1 text-xs font-semibold", ok ? "text-emerald-400" : "text-rose-400")}>
      {ok ? <ShieldCheck className="h-3.5 w-3.5" /> : <ShieldX className="h-3.5 w-3.5" />}{label}</span>;
  };
  return (
    <table className="w-full text-left text-sm">
      <thead className="text-[11px] uppercase tracking-wide text-slate-500">
        <tr><th className="pb-1 font-medium">Test</th><th className="pb-1 font-medium">Before</th><th className="pb-1 font-medium">After</th></tr>
      </thead>
      <tbody>
        {rows.map(({ before, after }) => {
          const t = (after ?? before)!;
          return (
            <tr key={t.test_id} className="border-t border-slate-800/80 align-top">
              <td className="py-1.5 pr-2 text-slate-300">
                {t.name}
                {t.privilege_map && <div className="text-[11px] text-slate-500">{t.privilege_map.actor} → {t.privilege_map.resource}</div>}
              </td>
              <td className="py-1.5 pr-2">{cell(before)}</td>
              <td className="py-1.5">{cell(after)}</td>
            </tr>
          );
        })}
      </tbody>
    </table>
  );
}

function Evidence({ stage, reportId }: { stage: Stage; reportId?: string }) {
  const parts: ReactNode[] = [];
  if (stage.error) parts.push(<p key="err" className="rounded-md bg-rose-500/10 px-3 py-2 text-sm text-rose-200">Backend error: {stage.error}</p>);
  if (stage.facts?.length) parts.push(
    <dl key="facts" className="grid grid-cols-[auto_minmax(0,1fr)] gap-x-3 gap-y-1 text-sm">
      {stage.facts.map(([k, v]) => <div key={k} className="contents"><dt className="text-slate-500">{k}</dt><dd className="break-all text-slate-300">{v}</dd></div>)}
    </dl>);
  if (stage.compare?.length) parts.push(
    <div key="cmp"><div className="mb-1 text-[11px] font-semibold uppercase tracking-wide text-slate-400">
      {stage.key === "replay" ? "Security tests — same exploit, before vs after" : "Regression tests — legitimate use, before vs after"}</div>
      <Compare rows={stage.compare} kind={stage.key === "replay" ? "security" : "regression"} /></div>);
  if (stage.tests?.length && !stage.compare?.length) parts.push(
    <div key="tests"><div className="mb-1 text-[11px] font-semibold uppercase tracking-wide text-slate-400">Security tests (exploit attempts)</div>
      <ul className="divide-y divide-slate-800/80 text-sm">{stage.tests.map((t) => <TestLine key={t.test_id} t={t} showExploit />)}</ul></div>);
  if (stage.key === "regression" && stage.tests?.length) parts.push(
    <div key="regdetail"><div className="mb-1 text-[11px] font-semibold uppercase tracking-wide text-slate-400">After the patch: expected vs observed</div>
      <ul className="divide-y divide-slate-800/80 text-sm">{stage.tests.map((t) => <TestLine key={t.test_id} t={t} />)}</ul></div>);
  if (stage.phase && (stage.key === "replay" || stage.key === "reproduce")) parts.push(
    <p key="sum" className="text-xs text-slate-500">
      Runner summary: security {stage.phase.security_tests.passed}/{stage.phase.security_tests.total} passed · regression {stage.phase.regression_tests.passed}/{stage.phase.regression_tests.total} passed
    </p>);
  if (stage.reasons?.length) parts.push(
    <div key="reasons"><div className="mb-1 text-[11px] font-semibold uppercase tracking-wide text-slate-400">Reasons reported by the testing runner</div>
      <ul className="list-disc space-y-0.5 pl-5 text-sm text-slate-300">{stage.reasons.map((r) => <li key={r}>{r}</li>)}</ul></div>);
  if (stage.diff) parts.push(<div key="diff" className="text-xs"><DiffView diff={stage.diff} /></div>);
  if (stage.key === "verdict" && reportId && stage.status !== "pending" && stage.status !== "running") parts.push(
    <Link key="report" className="inline-block text-sm text-sky-400 hover:underline" to={`/verification/${reportId}`}>Open verification report →</Link>);
  return parts.length ? <div className="space-y-3">{parts}</div>
    : <p className="text-sm text-slate-500">No evidence recorded for this stage yet.</p>;
}

function StageRow({ stage, index, last, open, onToggle, reportId }: {
  stage: Stage; index: number; last: boolean; open: boolean; onToggle: () => void; reportId?: string;
}) {
  const s = STATUS[stage.status];
  const StageIcon = STAGE_ICON[stage.key];
  const panelId = `stage-${stage.key}`;
  return (
    <li className="relative flex gap-4">
      {!last && <span aria-hidden className={cx("absolute left-[19px] top-10 h-[calc(100%-2.5rem)] w-px",
        stage.status === "passed" ? "bg-emerald-500/40" : stage.status === "failed" ? "bg-rose-500/40" : "bg-slate-700")} />}
      <span className={cx("relative z-10 mt-0.5 flex h-10 w-10 shrink-0 items-center justify-center rounded-full border-2", s.ring)}>
        <StageIcon className={cx("h-4 w-4", s.text)} />
        <span className="absolute -bottom-1 -right-1 rounded-full bg-slate-950">
          <s.Icon className={cx("h-4 w-4", s.text, stage.status === "running" && "animate-spin")} />
        </span>
      </span>
      <div className={cx("mb-4 min-w-0 flex-1 rounded-xl border transition-colors",
        open ? "border-slate-700 bg-slate-900/80" : "border-slate-800 bg-slate-900/40 hover:border-slate-700")}>
        <button type="button" onClick={onToggle} aria-expanded={open} aria-controls={panelId}
          className="flex w-full items-start gap-3 rounded-xl px-4 py-3 text-left focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-500">
          <div className="min-w-0 flex-1">
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-xs tabular-nums text-slate-500">{index + 1}</span>
              <span className="font-medium text-slate-100">{stage.title}</span>
              <Chip status={stage.status} />
            </div>
            <p className="mt-1 text-sm text-slate-400">{stage.summary}</p>
            {stage.timing.length > 0 && (
              <div className="mt-1 flex flex-wrap gap-x-4 gap-y-0.5 text-[11px] text-slate-500">
                {stage.timing.map((t) => (
                  <span key={t.label} title={t.note}>
                    <Clock className="mr-1 inline h-3 w-3" />{t.label}{t.at && ` ${fmtDate(t.at)}`}{fmtMs(t.durationMs) && ` · ${fmtMs(t.durationMs)}`}{t.note && ` (${t.note})`}
                  </span>
                ))}
              </div>
            )}
          </div>
          <ChevronDown className={cx("mt-1 h-4 w-4 shrink-0 text-slate-500 transition-transform", open && "rotate-180")} />
        </button>
        {open && <div id={panelId} className="border-t border-slate-800 px-4 py-3"><Evidence stage={stage} reportId={reportId} /></div>}
      </div>
    </li>
  );
}

const OVERALL: Record<string, string> = { running: "In progress", completed: "Completed", error: "Run error", notStarted: "Not yet verified" };

/** Live Attack Timeline. Reconstructed from recorded runs; never simulates progress or computes a verdict. */
export function AttackTimeline(props: TimelineInput) {
  const stages = buildTimeline(props);
  const proof: VerificationRunDetail | null | undefined = props.proof;
  const [open, setOpen] = useState<Set<StageKey>>(new Set());
  const signature = stages.map((s) => s.status).join(",");

  // When statuses change, open what matters: failures, the verdict, or the stage awaiting the user.
  // Keyed on the status signature so a user's manual expand/collapse is kept between re-renders.
  useEffect(() => {
    const auto = stages.filter((s) => s.status === "failed" || s.status === "awaiting" || s.status === "partial"
      || (s.key === "verdict" && s.status === "passed")).map((s) => s.key);
    setOpen(new Set(auto));
  }, [signature]);

  const toggle = (k: StageKey) => setOpen((prev) => { const n = new Set(prev); if (n.has(k)) n.delete(k); else n.add(k); return n; });
  const overall = props.running ? "running" : proof ? (proof.status === "ERROR" ? "error" : "completed") : "notStarted";
  const recorded = stages.filter((s) => !["pending", "running"].includes(s.status)).length;
  const runId = proof?.id ?? props.baseline?.id;

  return (
    <section aria-label="Live Attack Timeline" className="rounded-xl border border-slate-800 bg-slate-950 p-4 sm:p-5">
      <header className="mb-4 space-y-3">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <h2 className="text-base font-semibold text-white">Live Attack Timeline</h2>
            <p className="text-xs text-slate-400">{vulnLabel(props.scenario)}{runId && <> · run <span className="font-mono">{runId.slice(0, 8)}</span></>}</p>
          </div>
          <div className="flex flex-wrap items-center gap-2 text-xs">
            <span className={cx("rounded-full px-2 py-0.5 font-semibold ring-1 ring-inset",
              overall === "running" ? "bg-sky-500/15 text-sky-300 ring-sky-500/40" : overall === "error" ? "bg-rose-500/15 text-rose-300 ring-rose-500/40" : "bg-slate-700/30 text-slate-300 ring-slate-600")}>
              {OVERALL[overall]}
            </span>
            {proof && <VerdictBadge verdict={proof.verdict as Verdict | null} />}
          </div>
        </div>
        <div className="flex items-center gap-1.5" aria-label={`${recorded} of ${stages.length} stages recorded`}>
          {stages.map((s) => (
            <span key={s.key} title={`${s.title}: ${STATUS[s.status].label}`}
              className={cx("h-1.5 flex-1 rounded-full",
                { passed: "bg-emerald-500", failed: "bg-rose-500", running: "bg-sky-500 animate-pulse", awaiting: "bg-amber-500", partial: "bg-amber-500",
                  pending: "bg-slate-800", skipped: "bg-slate-700", blocked: "bg-slate-600" }[s.status])} />
          ))}
          <span className="ml-2 shrink-0 text-[11px] text-slate-500">{recorded}/{stages.length} recorded</span>
        </div>
        <p className="text-[11px] leading-relaxed text-slate-500">
          Recorded verification sequence, rebuilt from stored results. The backend runs each step as one request and does not stream
          events, so stages update when a request completes. Statuses and the verdict come from the testing runner; nothing is simulated.
        </p>
      </header>
      <ol>
        {stages.map((s, i) => (
          <StageRow key={s.key} stage={s} index={i} last={i === stages.length - 1} open={open.has(s.key)} onToggle={() => toggle(s.key)} reportId={proof?.id} />
        ))}
      </ol>
    </section>
  );
}
