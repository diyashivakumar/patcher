import { Fingerprint } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { OUTCOME_LABEL, RunPicker } from "../components/GauntletParts";
import { Card, cx, Empty, ErrorBox, fmtDate, Loading, PageHeader, Pill, Stat, VerdictBadge, vulnLabel } from "../components/ui";
import { useApi } from "../hooks/useApi";
import { api } from "../services/api";
import type { CanaryRecordInfo, Forensics as ForensicsData, LedgerRow, VulnType } from "../types/api";

const PHASE_LABEL: Record<string, string> = { before_patch: "Before patch", after_patch: "After patch", baseline: "Original (baseline)" };
// Fixed chronological order: JSONB in PostgreSQL does not preserve object key order.
const PHASE_ORDER = ["baseline", "before_patch", "after_patch"];
const orderedPhases = (f: ForensicsData) => PHASE_ORDER.filter((p) => p in f.phases);

function exposedIn(f: ForensicsData, phase: string, recordId: string) {
  const rows = f.phases[phase]?.ledger.filter((r) => r.record_id === recordId && !r.authorized) ?? [];
  return { rows, fields: [...new Set(rows.flatMap((r) => r.exposed_fields))].sort() };
}

function RecordCompare({ f, rec, selected, onSelect }: { f: ForensicsData; rec: CanaryRecordInfo; selected: boolean; onSelect: () => void }) {
  const phases = orderedPhases(f);
  const kept = f.comparison?.legitimate_access_kept.includes(rec.record_id);
  const lost = f.comparison?.legitimate_access_lost.includes(rec.record_id);
  return (
    <button onClick={onSelect} aria-pressed={selected}
      className={cx("w-full rounded-xl border p-4 text-left transition", selected ? "border-sky-500/60 bg-slate-900" : "border-slate-800 bg-slate-900/50 hover:border-slate-700")}>
      <div className="flex items-center justify-between gap-2">
        <span className="font-mono font-semibold text-slate-100">{rec.record_id}</span>
        <span className="text-xs text-slate-500">owner {rec.owner}</span>
      </div>
      <div className="mt-3 space-y-2">
        {phases.map((ph) => {
          const e = exposedIn(f, ph, rec.record_id);
          return (
            <div key={ph} className="flex items-center justify-between gap-2 text-sm">
              <span className="text-slate-400">{PHASE_LABEL[ph] ?? ph}</span>
              {e.rows.length
                ? <Pill className="bg-rose-500/15 text-rose-300 ring-rose-500/40">Exposed · {e.fields.join(", ")}</Pill>
                : <Pill className="bg-emerald-500/15 text-emerald-300 ring-emerald-500/40">Not exposed</Pill>}
            </div>
          );
        })}
        {(kept || lost) && (
          <div className="flex items-center justify-between gap-2 text-sm">
            <span className="text-slate-400">Owner access after patch</span>
            {lost ? <Pill className="bg-rose-500/15 text-rose-300 ring-rose-500/40">Lost</Pill> : <Pill className="bg-emerald-500/15 text-emerald-300 ring-emerald-500/40">Kept</Pill>}
          </div>
        )}
      </div>
    </button>
  );
}

function Inspector({ f, rec }: { f: ForensicsData; rec: CanaryRecordInfo }) {
  const rows = orderedPhases(f).flatMap((p) => f.phases[p].ledger.filter((r) => r.record_id === rec.record_id));
  return (
    <Card title={`Inspect ${rec.record_id} — which synthetic fields were returned`}>
      <dl className="mb-4 grid grid-cols-[auto_minmax(0,1fr)] gap-x-4 gap-y-1 text-sm">
        <dt className="text-slate-500">Owner</dt><dd>{rec.owner}</dd>
        <dt className="text-slate-500">Type</dt><dd>{rec.record_type.replace(/_/g, " ")}</dd>
        <dt className="text-slate-500">Authorised readers</dt><dd>{rec.authorized_actors.join(", ")}</dd>
        <dt className="text-slate-500">Canary marker</dt><dd className="break-all font-mono text-sky-300">{rec.marker}</dd>
      </dl>
      <table className="mb-4 w-full text-left text-sm">
        <thead className="text-xs uppercase tracking-wide text-slate-500"><tr><th className="pb-1">Field</th><th className="pb-1">Sensitivity</th><th className="pb-1">Field marker</th><th className="pb-1">Returned to unauthorised actors</th></tr></thead>
        <tbody>
          {rec.fields.map((fld) => {
            const hits = rows.filter((r) => !r.authorized && r.exposed_fields.includes(fld.name));
            return (
              <tr key={fld.name} className="border-t border-slate-800">
                <td className="py-1.5">{fld.name}</td>
                <td className="py-1.5"><Pill className={fld.sensitivity === "restricted" ? "bg-rose-500/10 text-rose-200 ring-rose-500/30" : "bg-amber-500/10 text-amber-200 ring-amber-500/30"}>{fld.sensitivity}</Pill></td>
                <td className="py-1.5 font-mono text-xs text-slate-400">{fld.marker}</td>
                <td className="py-1.5 text-xs">{hits.length ? <span className="text-rose-300">{[...new Set(hits.map((h) => `${PHASE_LABEL[h.phase] ?? h.phase}: ${h.actor}`))].join(" · ")}</span> : <span className="text-emerald-300">never</span>}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
      <p className="text-xs text-slate-500">Evidence is the canary markers found in the actual response, with the actor, request and status code. Response bodies are not stored.</p>
    </Card>
  );
}

function Ledger({ rows, highlight }: { rows: LedgerRow[]; highlight?: string | null }) {
  if (!rows.length) return <p className="text-sm text-slate-500">No canary data appeared in any response in this phase.</p>;
  return (
    <div className="overflow-x-auto">
      <table className="w-full min-w-[820px] text-left text-sm">
        <thead className="text-xs uppercase tracking-wide text-slate-500">
          <tr><th className="pb-2">Actor</th><th className="pb-2">Record (owner)</th><th className="pb-2">Fields</th><th className="pb-2">Status</th><th className="pb-2">Request</th><th className="pb-2">Canary match</th><th className="pb-2">Evidence ref</th></tr>
        </thead>
        <tbody>
          {rows.map((r, i) => (
            <tr key={`${r.evidence_ref}-${r.record_id}-${i}`} className={cx("border-t border-slate-800 align-top", highlight && r.variant_id === highlight && "bg-sky-500/10")}>
              <td className="py-2 pr-3">{r.actor}</td>
              <td className="py-2 pr-3 font-mono">{r.record_id} <span className="font-sans text-xs text-slate-500">({r.record_owner})</span></td>
              <td className="py-2 pr-3">{r.exposed_fields.join(", ")}</td>
              <td className="py-2 pr-3">{r.authorized
                ? <Pill className="bg-emerald-500/15 text-emerald-300 ring-emerald-500/40">Authorised</Pill>
                : <Pill className="bg-rose-500/15 text-rose-300 ring-rose-500/40">{OUTCOME_LABEL[r.exposure_status] ?? r.exposure_status}</Pill>}</td>
              <td className="py-2 pr-3 font-mono text-xs text-slate-400">{r.request} · {r.status_code ?? "—"}</td>
              <td className="py-2 pr-3 font-mono text-[11px] text-slate-400">{r.canary_match.length ? r.canary_match.join(" ") : r.detection === "record_identity" ? "record id returned; markers not visible (fields transformed)" : "—"}</td>
              <td className="py-2 font-mono text-[11px] text-slate-500">{r.evidence_ref}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function Forensics() {
  const [params, setParams] = useSearchParams();
  const runs = useApi(() => api.listRuns());
  const scenario = (params.get("scenario") as VulnType) || "idor";
  const runId = params.get("run") ?? "";
  const highlight = params.get("variant");
  const run = useApi(() => (runId ? api.getRun(runId) : Promise.resolve(null)), [runId]);
  const [selected, setSelected] = useState<string | null>(null);
  const [phase, setPhase] = useState<string>("");

  useEffect(() => {
    if (run.data && run.data.scenario !== scenario) setParams({ scenario: run.data.scenario, run: run.data.id }, { replace: true });
  }, [run.data, scenario, setParams]);
  useEffect(() => {
    if (!runId && runs.data) {
      const first = runs.data.find((r) => r.scenario === scenario);
      if (first) setParams({ scenario, run: first.id }, { replace: true });
    }
  }, [runId, runs.data, scenario, setParams]);

  const r = run.data;
  const f = r?.forensics ?? null;
  const phases = useMemo(() => (f ? orderedPhases(f) : []), [f]);
  useEffect(() => { setPhase(phases[0] ?? ""); setSelected(null); }, [r?.id, phases]);
  const before = f?.phases.before_patch ?? f?.phases.baseline;
  const after = f?.phases.after_patch;
  const selectedRec = f?.canary_records.find((c) => c.record_id === selected) ?? null;

  return (
    <>
      <PageHeader title="Data Exposure Forensics" subtitle="Don't just detect the breach. Show exactly which synthetic records and fields came back in the actual responses." />
      <Card className="mb-4">
        <RunPicker runs={runs.data} scenario={scenario} runId={runId} includeBaseline
          onScenario={(s) => setParams({ scenario: s })} onRun={(id) => setParams({ scenario, run: id })} />
        <ErrorBox error={runs.error} onRetry={runs.reload} />
      </Card>
      {runs.data && !runs.data.some((x) => x.scenario === scenario) && (
        <Card><Empty>No {vulnLabel(scenario)} verification runs yet. Run the exploit in the <Link className="text-sky-400 hover:underline" to={`/replay?scenario=${scenario}`}>Attack Replay Lab</Link>.</Empty></Card>
      )}
      {run.loading && runId && !r && <Loading />}
      <ErrorBox error={run.error} onRetry={run.reload} />

      {r && !f && <Card><p className="text-sm text-slate-400">This run was recorded before Data Exposure Forensics existed. Run the exploit or Proof-of-Fix again to record an exposure ledger.</p></Card>}

      {r && f && (
        <div className="space-y-4">
          <div className="flex flex-wrap items-center gap-2 text-sm text-slate-400">
            <Fingerprint className="h-4 w-4 text-sky-400" /> Run {r.id.slice(0, 8)} · {r.kind === "proof_of_fix" ? "Proof-of-Fix" : "Baseline"} · {fmtDate(r.created_at)}
            {r.kind === "proof_of_fix" && <VerdictBadge verdict={r.verdict} />}
            <Link className="ml-auto text-sky-400 hover:underline" to={`/verification/${r.id}`}>Verification report →</Link>
          </div>
          <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
            <Stat label={`Records exposed · ${before === f.phases.baseline ? "original" : "before"}`} value={before?.unauthorized_records_exposed.length ?? 0} accent={before?.unauthorized_records_exposed.length ? "text-rose-300" : undefined} />
            <Stat label="Protected fields · before" value={before?.protected_fields_exposed.length ?? 0} accent={before?.protected_fields_exposed.length ? "text-rose-300" : undefined} />
            {after ? <>
              <Stat label="Records exposed · after" value={after.unauthorized_records_exposed.length} accent={after.unauthorized_records_exposed.length ? "text-rose-300" : "text-emerald-300"} />
              {before?.legitimate_records_accessible.length
                ? <Stat label="Legit records still accessible" value={`${after.legitimate_records_accessible.length}/${before.legitimate_records_accessible.length}`}
                    hint={f.comparison?.legitimate_access_lost.length ? `lost: ${f.comparison.legitimate_access_lost.join(", ")}` : "owners and authorised readers keep access"}
                    accent={f.comparison?.legitimate_access_lost.length ? "text-rose-300" : "text-emerald-300"} />
                : <Stat label="Legit records still accessible" value="—" hint="No legitimate request in this scenario reads a canary record; see legitimate-use tests" />}
            </> : <Stat label="After patch" value="—" hint="Baseline runs test the original app only" />}
          </div>

          <Card title="Canary records — before vs after">
            <div className="grid gap-3 md:grid-cols-3">
              {f.canary_records.map((rec) => (
                <RecordCompare key={rec.record_id} f={f} rec={rec} selected={selected === rec.record_id}
                  onSelect={() => setSelected(selected === rec.record_id ? null : rec.record_id)} />
              ))}
            </div>
            <p className="mt-3 text-xs text-slate-500">Select a record to inspect which of its fields were returned. Fabricated data only.</p>
          </Card>
          {selectedRec && <Inspector f={f} rec={selectedRec} />}

          <Card title="Exposure ledger" actions={
            <div className="flex gap-1" role="tablist">
              {phases.map((ph) => (
                <button key={ph} role="tab" aria-selected={phase === ph} onClick={() => setPhase(ph)}
                  className={cx("rounded-md px-2.5 py-1 text-xs", phase === ph ? "bg-sky-500/15 text-sky-300" : "text-slate-400 hover:text-slate-200")}>
                  {PHASE_LABEL[ph] ?? ph} ({f.phases[ph].ledger.length})
                </button>
              ))}
            </div>}>
            {phase && <Ledger rows={f.phases[phase].ledger} highlight={highlight} />}
          </Card>
        </div>
      )}
    </>
  );
}
