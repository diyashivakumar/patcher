import { ChevronDown, Play, ShieldAlert, Swords } from "lucide-react";
import { useEffect, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { describeInput, GauntletChip, OUTCOME_LABEL, RunPicker } from "../components/GauntletParts";
import { Button, Card, cx, Empty, ErrorBox, fmtDate, Loading, PageHeader, Pill, VerdictBadge, vulnLabel } from "../components/ui";
import { useAction, useApi } from "../hooks/useApi";
import { api } from "../services/api";
import type { GauntletCase, VariantPhaseView, VulnType } from "../types/api";

function PhaseResult({ view, kind }: { view: VariantPhaseView | null; kind: "attack" | "legit" }) {
  if (!view) return <span className="text-slate-600">not run</span>;
  const bad = kind === "attack" ? view.exploited : !view.legit_ok;
  const label = kind === "attack" ? (view.exploited ? "Exploited" : "No protected data") : view.legit_ok ? "Works" : "Broken";
  return (
    <div>
      <span className={cx("text-sm font-semibold", bad ? "text-rose-300" : "text-emerald-300")}>{label}</span>
      <div className="text-xs text-slate-500">HTTP {view.status_code ?? "—"} · {OUTCOME_LABEL[view.exposure_outcome] ?? view.exposure_outcome}</div>
    </div>
  );
}

function RecordList({ view }: { view: VariantPhaseView | null }) {
  if (!view) return <p className="text-xs text-slate-500">Not executed.</p>;
  if (view.error) return <p className="text-xs text-amber-300">{view.error}</p>;
  if (view.injection_probe_hit && !view.records.length) return <p className="text-xs text-rose-300">Injection probe output found: the injected SQL was executed.</p>;
  if (!view.records.length) return <p className="text-xs text-slate-500">No canary markers in the response ({view.response_bytes} bytes inspected).</p>;
  return (
    <ul className="space-y-1 text-xs">
      {view.records.map((r) => (
        <li key={r.record_id} className={r.authorized ? "text-emerald-300" : "text-rose-300"}>
          {r.record_id}: {r.exposed_fields.join(", ")} {r.authorized ? "(authorised for this actor)" : "— protected"}
          {r.detection === "record_identity" && " · detected by record id (markers not visible)"}
        </li>
      ))}
    </ul>
  );
}

function CaseRow({ c, runId }: { c: GauntletCase; runId: string }) {
  const [open, setOpen] = useState(c.status === "bypass" || c.status === "regression_failed");
  return (
    <>
      <tr className={cx("border-t border-slate-800 align-top", c.status === "bypass" && "bg-rose-500/5")}>
        <td className="py-2.5 pl-2">
          <button className="text-slate-500 hover:text-slate-200" onClick={() => setOpen(!open)} aria-expanded={open} aria-label={`Details for ${c.variation}`}>
            <ChevronDown className={cx("h-4 w-4 transition-transform", open && "rotate-180")} />
          </button>
        </td>
        <td className="py-2.5 pr-3">
          <div className="text-slate-200">{c.variation}</div>
          <div className="font-mono text-[11px] text-slate-500">{c.variant_id}{c.regression_case_id && " · saved regression case"}</div>
        </td>
        <td className="py-2.5 pr-3"><Pill className={c.kind === "attack" ? "bg-rose-500/10 text-rose-200 ring-rose-500/30" : "bg-sky-500/10 text-sky-200 ring-sky-500/30"}>{c.kind === "attack" ? "Exploit" : "Legit use"}</Pill></td>
        <td className="py-2.5 pr-3"><PhaseResult view={c.before} kind={c.kind} /></td>
        <td className="py-2.5 pr-3"><PhaseResult view={c.after} kind={c.kind} /></td>
        <td className="py-2.5 pr-2"><GauntletChip status={c.status} /></td>
      </tr>
      {open && (
        <tr className="border-t border-slate-800/50">
          <td />
          <td colSpan={5} className="pb-4 pr-2">
            <div className="grid gap-3 rounded-lg bg-slate-950 p-3 md:grid-cols-2">
              <div className="space-y-1 text-xs md:col-span-2">
                <div><span className="text-slate-500">Input (synthetic):</span> <code className="whitespace-pre-wrap break-all text-sky-300">{describeInput(c.input)}</code></div>
                <div><span className="text-slate-500">Expected:</span> <span className="text-slate-300">{c.expected}</span></div>
                <div><span className="text-slate-500">Result:</span> <span className="text-slate-300">{c.reason}</span></div>
                <div className="text-slate-500">{c.description}</div>
              </div>
              <div><div className="mb-1 text-[11px] font-semibold uppercase tracking-wide text-slate-400">Original app</div><RecordList view={c.before} /></div>
              <div><div className="mb-1 text-[11px] font-semibold uppercase tracking-wide text-slate-400">Patched app</div><RecordList view={c.after} /></div>
              {(c.before?.records.length || c.after?.records.length) ? (
                <Link className="text-xs text-sky-400 hover:underline md:col-span-2" to={`/forensics?run=${runId}&variant=${c.variant_id}`}>Open in the Exposure Ledger →</Link>
              ) : null}
            </div>
          </td>
        </tr>
      )}
    </>
  );
}

export function Gauntlet() {
  const [params, setParams] = useSearchParams();
  const navigate = useNavigate();
  const runs = useApi(() => api.listRuns({ kind: "proof_of_fix" }));
  const scenario = (params.get("scenario") as VulnType) || "sqli";
  const runId = params.get("run") ?? "";
  const run = useApi(() => (runId ? api.getRun(runId) : Promise.resolve(null)), [runId]);
  const cases = useApi(() => api.listRegressionCases(scenario), [scenario, run.data?.id]);
  const patch = useApi(() => (run.data?.patch_id ? api.getPatch(run.data.patch_id) : Promise.resolve(null)), [run.data?.patch_id]);
  const rerun = useAction();

  // Pick the newest run for the scenario when none is selected; follow the run's scenario when one is.
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
  const g = r?.gauntlet;
  const canRerun = patch.data && ["APPLIED", "VERIFIED", "REJECTED"].includes(patch.data.status);
  const runGauntlet = async () => {
    if (!r?.patch_id) return;
    const next = await rerun.run(() => api.runProofOfFix(r.patch_id!));
    if (next) { await runs.reload(); navigate(`/gauntlet?scenario=${next.scenario}&run=${next.id}`); }
  };
  const bypassCases = g?.cases.filter((c) => c.status === "bypass") ?? [];

  return (
    <>
      <PageHeader title="Exploit Variant Gauntlet" subtitle="One exploit is not enough. Every patch is replayed against validated variations of the attack, on the original and the patched app." />
      <Card className="mb-4">
        <RunPicker runs={runs.data} scenario={scenario} runId={runId}
          onScenario={(s) => setParams({ scenario: s })} onRun={(id) => setParams({ scenario, run: id })} />
        <ErrorBox error={runs.error} onRetry={runs.reload} />
      </Card>

      {runs.data && !runs.data.some((x) => x.scenario === scenario) && (
        <Card><Empty>No {vulnLabel(scenario)} Proof-of-Fix runs yet. Apply a patch in the <Link className="text-sky-400 hover:underline" to={`/replay?scenario=${scenario}`}>Attack Replay Lab</Link> and run Proof-of-Fix.</Empty></Card>
      )}
      {run.loading && runId && !r && <Loading />}
      <ErrorBox error={run.error} onRetry={run.reload} />

      {r && (
        <div className="space-y-4">
          <Card title={<span className="inline-flex items-center gap-2"><Swords className="h-4 w-4 text-sky-400" />Run {r.id.slice(0, 8)} · {fmtDate(r.created_at)}</span>}
            actions={<div className="flex flex-wrap items-center gap-2">
              <VerdictBadge verdict={r.verdict} />
              <Button onClick={runGauntlet} busy={rerun.busy} disabled={!canRerun} title={canRerun ? "" : "The patch is no longer applied"}>
                <Play className="h-4 w-4" />Run Gauntlet again
              </Button>
            </div>}>
            {!canRerun && patch.data && <p className="mb-2 text-xs text-slate-500">This run's patch is {patch.data.status.replace("_", " ").toLowerCase()}, so it cannot be re-run. Apply a patch in the Lab first.</p>}
            <ErrorBox error={rerun.error} />
            {!g ? (
              <p className="text-sm text-slate-400">This run was recorded before the Gauntlet existed{canRerun ? ". Click “Run Gauntlet again” to test this patch now." : "."}</p>
            ) : (
              <>
                <div className="flex flex-wrap gap-3">
                  {(["blocked", "bypass", "works", "regression_failed", "inconclusive", "invalid"] as const).map((s) => (
                    <div key={s} className="rounded-lg border border-slate-800 bg-slate-950 px-3 py-2">
                      <GauntletChip status={s} /><div className="mt-1 text-2xl font-semibold tabular-nums text-white">{g.counts[s]}</div>
                    </div>
                  ))}
                </div>
                <p className="mt-3 text-sm text-slate-400">
                  {g.valid_attack_variants} exploit variant(s) reproduced on the original app and were replayed on the patched copy.
                  Invalid variants did not reproduce on the original and are never counted as blocks. Legitimate-use regression tests:{" "}
                  <b className={r.regressions_pass_after_patch ? "text-emerald-300" : "text-rose-300"}>{r.regressions_pass_after_patch ? "passing" : "failing"}</b>.
                </p>
                <ul className="mt-2 list-disc pl-5 text-sm text-slate-300">{r.verdict_reasons.map((x) => <li key={x}>{x}</li>)}</ul>
              </>
            )}
          </Card>

          {bypassCases.length > 0 && (
            <Card title={<span className="inline-flex items-center gap-2 text-rose-200"><ShieldAlert className="h-4 w-4" />Surviving bypasses — patch requires review</span>}>
              <div className="space-y-3">
                {bypassCases.map((c) => (
                  <div key={c.variant_id} className="rounded-lg border border-rose-500/30 bg-rose-500/5 p-3 text-sm">
                    <div className="flex flex-wrap items-center gap-2"><b className="text-rose-100">{c.variation}</b><span className="font-mono text-xs text-slate-400">{c.variant_id}</span><span className="text-xs text-slate-400">{vulnLabel(c.scenario)}</span></div>
                    <div className="mt-1 whitespace-pre-wrap break-all font-mono text-xs text-sky-300">{describeInput(c.input)}</div>
                    <div className="mt-1 text-slate-300">Expected: {c.expected}. Actual: HTTP {c.after?.status_code}, {OUTCOME_LABEL[c.after?.exposure_outcome ?? ""] ?? c.after?.exposure_outcome} — {c.after?.records.filter((x) => !x.authorized).map((x) => `${x.record_id} (${x.exposed_fields.join(", ")})`).join("; ")}</div>
                    <div className="mt-1 text-rose-200">{c.reason}</div>
                  </div>
                ))}
              </div>
              <p className="mt-3 text-xs text-slate-500">PatchProof never edits or approves a patch automatically. Each bypass is saved as a regression case and replayed on every future verification.</p>
            </Card>
          )}

          {g && (
            <Card title="Variant matrix — same request, original vs patched">
              <div className="overflow-x-auto">
                <table className="w-full min-w-[760px] text-left text-sm">
                  <thead className="text-xs uppercase tracking-wide text-slate-500">
                    <tr><th className="w-8" /><th className="pb-2">Variant</th><th className="pb-2">Type</th><th className="pb-2">Original app</th><th className="pb-2">Patched app</th><th className="pb-2">Result</th></tr>
                  </thead>
                  <tbody>{g.cases.map((c) => <CaseRow key={c.variant_id} c={c} runId={r.id} />)}</tbody>
                </table>
              </div>
            </Card>
          )}

          <Card title={`Preserved regression cases (${vulnLabel(scenario)})`}>
            <ErrorBox error={cases.error} onRetry={cases.reload} />
            {cases.data?.length === 0 && <p className="text-sm text-slate-500">No bypass has been confirmed for this scenario yet, so no regression cases are saved.</p>}
            {!!cases.data?.length && (
              <ul className="divide-y divide-slate-800 text-sm">
                {cases.data.map((c) => (
                  <li key={c.id} className="py-2">
                    <div className="text-slate-200">{c.variation}</div>
                    <div className="whitespace-pre-wrap break-all font-mono text-xs text-sky-300">{describeInput(c.input)}</div>
                    <div className="text-xs text-slate-500">
                      from {c.source_variant_id} · seen {c.times_seen}× · first found {fmtDate(c.created_at)}
                      {c.source_run_id && <> · <Link className="text-sky-400 hover:underline" to={`/gauntlet?run=${c.source_run_id}`}>source run</Link></>}
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </Card>
        </div>
      )}
    </>
  );
}
