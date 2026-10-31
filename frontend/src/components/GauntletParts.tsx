import { Fingerprint, Swords } from "lucide-react";
import { Link } from "react-router-dom";
import type { GauntletStatus, VariantInput, VerificationRun, VerificationRunDetail, VulnType } from "../types/api";
import { Card, cx, fmtDate, Pill, vulnLabel } from "./ui";

export const GAUNTLET_STATUS: Record<GauntletStatus, { label: string; cls: string }> = {
  blocked: { label: "Blocked", cls: "bg-emerald-500/15 text-emerald-300 ring-emerald-500/40" },
  works: { label: "Legit OK", cls: "bg-emerald-500/15 text-emerald-300 ring-emerald-500/40" },
  bypass: { label: "Bypass detected", cls: "bg-rose-500/15 text-rose-300 ring-rose-500/40" },
  regression_failed: { label: "Regression failed", cls: "bg-rose-500/15 text-rose-300 ring-rose-500/40" },
  inconclusive: { label: "Inconclusive", cls: "bg-amber-500/15 text-amber-300 ring-amber-500/40" },
  invalid: { label: "Invalid test", cls: "bg-slate-700/40 text-slate-300 ring-slate-500" },
};

export const GauntletChip = ({ status }: { status: GauntletStatus | "pending" }) =>
  status === "pending"
    ? <Pill className="bg-slate-800 text-slate-400 ring-slate-700">Pending</Pill>
    : <Pill className={GAUNTLET_STATUS[status].cls}>{GAUNTLET_STATUS[status].label}</Pill>;

export const OUTCOME_LABEL: Record<string, string> = {
  rejected: "Rejected",
  accepted_no_protected_data: "No protected data",
  protected_record_exposed: "Record exposed",
  partial_field_exposure: "Partial fields exposed",
  multiple_records_exposed: "Multiple records exposed",
  inconclusive: "Inconclusive",
  authorized_access: "Authorised access",
  injection_executed: "Injected SQL executed",
  record_returned_markers_not_visible: "Record returned (fields transformed)",
};

/** Human-readable request line for a variant input (all synthetic). Params are shown decoded so the
 *  exact payload is visible; raw_query is shown as sent, because its encoding IS the variation. */
export function describeInput(i: VariantInput) {
  const qs = i.raw_query ?? Object.entries(i.params ?? {}).map(([k, v]) => `${k}=${v}`).join("&");
  return `${i.method} ${i.path}${qs ? `?${qs}` : ""}  as ${i.actor}`;
}

/** Compact summary used in the Attack Replay Lab and on the verification page. Display only. */
export function GauntletSummaryCard({ run }: { run: VerificationRunDetail }) {
  const g = run.gauntlet;
  const f = run.forensics;
  if (!g && !f) {
    return (
      <Card title="Exploit Variant Gauntlet · Data Exposure Forensics">
        <p className="text-sm text-slate-400">Not recorded for this run (it predates the Gauntlet or the runner did not return it).</p>
      </Card>
    );
  }
  const before = f?.phases.before_patch ?? f?.phases.baseline;
  const after = f?.phases.after_patch;
  return (
    <Card title="Exploit Variant Gauntlet · Data Exposure Forensics"
      actions={<div className="flex gap-3 text-sm">
        {g && <Link className="inline-flex items-center gap-1 text-sky-400 hover:underline" to={`/gauntlet?run=${run.id}`}><Swords className="h-4 w-4" />Gauntlet</Link>}
        {f && <Link className="inline-flex items-center gap-1 text-sky-400 hover:underline" to={`/forensics?run=${run.id}`}><Fingerprint className="h-4 w-4" />Exposure ledger</Link>}
      </div>}>
      <div className="grid gap-4 md:grid-cols-2">
        {g && (
          <div>
            <div className="mb-2 flex flex-wrap gap-2">
              {(["blocked", "bypass", "works", "regression_failed", "inconclusive", "invalid"] as GauntletStatus[])
                .filter((s) => g.counts[s]).map((s) => (
                  <span key={s} className="inline-flex items-center gap-1"><GauntletChip status={s} /><span className="text-xs text-slate-400">×{g.counts[s]}</span></span>
                ))}
            </div>
            {g.bypasses.length > 0 ? (
              <p className="text-sm text-rose-200">{g.bypasses.length} variant(s) still exploit the patched app: {g.bypasses.join(", ")}. The patch needs review.</p>
            ) : (
              <p className="text-sm text-slate-400">{g.valid_attack_variants} valid exploit variant(s) tested{g.counts.invalid ? `; ${g.counts.invalid} invalid variant(s) not counted` : ""}.</p>
            )}
          </div>
        )}
        {before && (
          <div className="text-sm">
            <div className="text-slate-400">Unauthorised canary records exposed</div>
            <div className="mt-1 flex items-center gap-2">
              <span className={cx("rounded px-2 py-0.5 font-mono", before.unauthorized_records_exposed.length ? "bg-rose-500/15 text-rose-300" : "bg-slate-800 text-slate-300")}>
                before: {before.unauthorized_records_exposed.length}
              </span>
              {after && <>→<span className={cx("rounded px-2 py-0.5 font-mono", after.unauthorized_records_exposed.length ? "bg-rose-500/15 text-rose-300" : "bg-emerald-500/15 text-emerald-300")}>
                after: {after.unauthorized_records_exposed.length}
              </span></>}
            </div>
            {after && f?.comparison?.legitimate_access_lost.length ? (
              <p className="mt-2 text-rose-200">Legitimate access lost: {f.comparison.legitimate_access_lost.join(", ")}</p>
            ) : null}
          </div>
        )}
      </div>
      <p className="mt-3 text-xs text-slate-500">Summary of the testing runner's results. The verdict above comes from the runner, not from this panel.</p>
    </Card>
  );
}

/** Scenario + recorded-run selector shared by the Gauntlet and Forensics pages. */
export function RunPicker({ runs, scenario, runId, onScenario, onRun, includeBaseline }: {
  runs: VerificationRun[] | null; scenario: VulnType; runId: string; onScenario: (s: VulnType) => void; onRun: (id: string) => void;
  includeBaseline?: boolean;
}) {
  const options = (runs ?? []).filter((r) => r.scenario === scenario && (includeBaseline || r.kind === "proof_of_fix"));
  const select = "rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100";
  return (
    <div className="flex flex-wrap items-end gap-3">
      <label className="text-xs text-slate-400">Scenario<br />
        <select className={select} value={scenario} onChange={(e) => onScenario(e.target.value as VulnType)}>
          <option value="sqli">SQL Injection</option>
          <option value="idor">Broken Access Control (IDOR)</option>
        </select>
      </label>
      <label className="min-w-0 flex-1 text-xs text-slate-400">Verification run<br />
        <select className={cx(select, "w-full")} value={runId} onChange={(e) => onRun(e.target.value)} disabled={!options.length}>
          {!runs && <option value="">Loading runs…</option>}
          {runs && !options.length && <option value="">No {vulnLabel(scenario)} runs recorded</option>}
          {options.map((r) => (
            <option key={r.id} value={r.id}>
              {fmtDate(r.created_at)} · {r.kind === "proof_of_fix" ? `Proof-of-Fix ${r.verdict ?? ""}` : "Baseline"} · {r.id.slice(0, 8)}
            </option>
          ))}
        </select>
      </label>
    </div>
  );
}
