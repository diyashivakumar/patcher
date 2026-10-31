import { AlertTriangle, ArrowRight, Ban, Database, Fingerprint, KeyRound, Play, ShieldCheck, Swords } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { Button, Card, cx, ErrorBox, PageHeader, Pill } from "../components/ui";
import { useAction } from "../hooks/useApi";
import { api, USE_MOCKS } from "../services/api";
import type { ChainImpactResult, ChainMatrixRow, ChainStep } from "../types/api";

const STEP_ICON = [KeyRound, Fingerprint, Database];

/** breached (red) / blocked (green) / unreachable (grey), from the real step result. */
function stepState(step: ChainStep): "breached" | "blocked" | "unreachable" {
  if (!step.reached) return "unreachable";
  return step.succeeded ? "breached" : "blocked";
}

const STATE_STYLE = {
  breached: { ring: "border-rose-500 bg-rose-500/15", text: "text-rose-300", dot: "bg-rose-500", label: "Breached" },
  blocked: { ring: "border-emerald-500 bg-emerald-500/15", text: "text-emerald-300", dot: "bg-emerald-500", label: "Blocked" },
  unreachable: { ring: "border-slate-700 bg-slate-900", text: "text-slate-500", dot: "bg-slate-600", label: "Unreachable" },
  pending: { ring: "border-slate-800 bg-slate-900/40", text: "text-slate-600", dot: "bg-slate-700", label: "…" },
} as const;

function useCountUp(target: number, run: boolean, ms = 600) {
  const [n, setN] = useState(0);
  useEffect(() => {
    if (!run) { setN(0); return; }
    if (target === 0) { setN(0); return; }
    const start = performance.now();
    let raf = 0;
    const tick = (t: number) => {
      const p = Math.min(1, (t - start) / ms);
      setN(Math.round(p * target));
      if (p < 1) raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [target, run, ms]);
  return n;
}

function ChainNode({ step, index, revealed }: { step: ChainStep; index: number; revealed: boolean }) {
  const Icon = STEP_ICON[index] ?? KeyRound;
  const s = revealed ? STATE_STYLE[stepState(step)] : STATE_STYLE.pending;
  return (
    <div className={cx("flex w-56 shrink-0 flex-col rounded-xl border p-4 transition-all duration-500",
      s.ring, revealed ? "opacity-100" : "opacity-40")}>
      <div className="flex items-center gap-2">
        <span className={cx("flex h-9 w-9 items-center justify-center rounded-full border", s.ring)}>
          <Icon className={cx("h-4 w-4", s.text)} />
        </span>
        <div className="min-w-0">
          <div className="text-xs text-slate-500">Step {index + 1}</div>
          <div className="truncate text-sm font-medium text-slate-100">{step.name}</div>
        </div>
      </div>
      <div className="mt-3 flex items-center gap-2">
        <span className={cx("h-2 w-2 rounded-full", s.dot)} />
        <span className={cx("text-xs font-semibold", s.text)}>{s.label}</span>
      </div>
      {revealed && <p className="mt-2 text-xs leading-relaxed text-slate-400">{step.actual}</p>}
    </div>
  );
}

function Edge({ artifacts, active }: { artifacts: string[]; active: boolean }) {
  return (
    <div className="flex shrink-0 flex-col items-center justify-center px-1 pt-2">
      <ArrowRight className={cx("h-5 w-5 transition-colors", active ? "text-rose-400" : "text-slate-700")} />
      {artifacts.length > 0 && active && (
        <div className="mt-1 max-w-[7rem] space-y-0.5 text-center">
          {artifacts.map((a) => (
            <span key={a} className="block rounded bg-rose-500/15 px-1.5 py-0.5 font-mono text-[10px] text-rose-300">{a}</span>
          ))}
        </div>
      )}
    </div>
  );
}

function AttackGraph({ row, revealed }: { row: ChainMatrixRow; revealed: number }) {
  const steps = row.steps;
  // Stolen tokens flow out of step 1; the single replayed token flows out of step 2.
  const edgeArtifacts = [row.stolen, steps[1]?.stolen ?? []];
  return (
    <div className="overflow-x-auto pb-2">
      <div className="flex min-w-max items-stretch">
        {steps.map((step, i) => (
          <div key={step.step_id} className="flex items-stretch">
            <ChainNode step={step} index={i} revealed={i < revealed} />
            {i < steps.length - 1 && <Edge artifacts={edgeArtifacts[i] ?? []} active={i + 1 < revealed && steps[i].reached} />}
          </div>
        ))}
      </div>
    </div>
  );
}

function ReceiptRow({ label, value, run }: { label: string; value: number; run: boolean }) {
  const n = useCountUp(value, run);
  return (
    <div className="flex items-baseline justify-between border-b border-dashed border-slate-800 py-1.5">
      <span className="text-sm text-slate-400">{label}</span>
      <span className={cx("font-mono text-lg tabular-nums", value > 0 ? "text-rose-300" : "text-slate-300")}>{n}</span>
    </div>
  );
}

function BreachReceipt({ row, run }: { row: ChainMatrixRow; run: boolean }) {
  const b = row.breach_bill;
  return (
    <Card title={<span className="inline-flex items-center gap-2"><AlertTriangle className="h-4 w-4 text-amber-400" />Breach Exposure</span>}>
      <div className="font-mono text-xs text-slate-500">synthetic data · illustrative only</div>
      <div className="mt-2">
        <ReceiptRow label="Credentials stolen" value={b.credentials_stolen} run={run} />
        <ReceiptRow label="Private records exposed" value={b.records_exposed} run={run} />
        <ReceiptRow label="Protected fields exposed" value={b.fields_exposed} run={run} />
        <ReceiptRow label="Identities affected" value={b.owners_affected.length} run={run} />
      </div>
      {b.records.length > 0 && (
        <div className="mt-3 flex flex-wrap gap-1">
          {b.records.map((r) => <Pill key={r} className="bg-rose-500/10 text-rose-200 ring-rose-500/30">{r}</Pill>)}
        </div>
      )}
      <div className="mt-4 rounded-lg border border-slate-800 bg-slate-950 p-3">
        <div className="mb-1 text-[11px] font-semibold uppercase tracking-wide text-slate-500">DPDP Act, 2023 — reference</div>
        {b.dpdp_references.map((d) => (
          <div key={d.provision} className="mb-2 last:mb-0">
            <div className="text-xs text-slate-300">{d.provision}</div>
            <div className="text-xs text-amber-300">
              Up to {d.statutory_maximum_label} — <span className="italic">{d.caveat}</span>
            </div>
          </div>
        ))}
      </div>
    </Card>
  );
}

function FixMatrix({ result }: { result: ChainImpactResult }) {
  const best = result.best_single_fix?.copy_id;
  return (
    <Card title="Fix impact — how far the chain reaches per fix">
      <div className="overflow-x-auto">
        <table className="w-full min-w-[640px] text-left text-sm">
          <thead className="text-xs uppercase tracking-wide text-slate-500">
            <tr>
              <th className="pb-2">Fix applied</th><th className="pb-2">Chain reach</th>
              <th className="pb-2">Credentials</th><th className="pb-2">Records exposed</th><th className="pb-2">Outcome</th>
            </tr>
          </thead>
          <tbody>
            {result.matrix.map((m) => (
              <tr key={m.copy_id} className={cx("border-t border-slate-800", best === m.copy_id && "bg-emerald-500/5")}>
                <td className="py-2.5">
                  <span className="text-slate-200">{m.label}</span>
                  {best === m.copy_id && (
                    <Pill className="ml-2 bg-emerald-500/15 text-emerald-300 ring-emerald-500/40"><ShieldCheck className="h-3 w-3" />Best single fix</Pill>
                  )}
                </td>
                <td className="py-2.5 tabular-nums text-slate-300">{m.steps_reached} / {result.total_steps} steps</td>
                <td className="py-2.5 tabular-nums">{m.breach_bill.credentials_stolen}</td>
                <td className={cx("py-2.5 tabular-nums", m.breach_bill.records_exposed ? "text-rose-300" : "text-emerald-300")}>{m.breach_bill.records_exposed}</td>
                <td className="py-2.5">
                  {m.chain_succeeded
                    ? <Pill className="bg-rose-500/15 text-rose-300 ring-rose-500/40"><Swords className="h-3 w-3" />Breach reaches data</Pill>
                    : <Pill className="bg-emerald-500/15 text-emerald-300 ring-emerald-500/40"><Ban className="h-3 w-3" />Chain broken</Pill>}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {result.best_single_fix && (
        <p className="mt-3 text-sm text-slate-400">
          A single fix — <b className="text-emerald-300">{result.best_single_fix.label}</b> — stops the chain after
          {" "}{result.best_single_fix.steps_reached} of {result.total_steps} steps, exposing{" "}
          {result.best_single_fix.records_exposed} records. It breaks the chain earliest.
        </p>
      )}
    </Card>
  );
}

export function KillChain() {
  const act = useAction();
  const [result, setResult] = useState<ChainImpactResult | null>(null);
  const [revealed, setRevealed] = useState(0);
  const timer = useRef<ReturnType<typeof setInterval>>();

  const original = result?.matrix.find((m) => m.copy_id === "original") ?? null;

  const animate = (steps: number) => {
    setRevealed(0);
    clearInterval(timer.current);
    let i = 0;
    timer.current = setInterval(() => {
      i += 1;
      setRevealed(i);
      if (i >= steps) clearInterval(timer.current);
    }, 650);
  };
  useEffect(() => () => clearInterval(timer.current), []);

  const run = async () => {
    const r = await act.run(() => api.chainImpact());
    if (r) { setResult(r); animate(r.matrix.find((m) => m.copy_id === "original")?.steps.length ?? 0); }
  };

  return (
    <>
      <PageHeader
        title="Attack Kill-Chain"
        subtitle="One flaw rarely stands alone. Watch SQL injection steal a token, then broken access control turn it into a full breach — and see which single fix breaks the chain."
        actions={<Button onClick={run} busy={act.busy}><Play className="h-4 w-4" />Run attack chain</Button>}
      />
      {USE_MOCKS && (
        <div className="mb-4 rounded-lg border border-amber-500/40 bg-amber-500/10 p-3 text-xs text-amber-200">
          Mock mode: showing a cached chain run. Start the backend for a live run.
        </div>
      )}
      <ErrorBox error={act.error} onRetry={run} />

      {!result && !act.busy && (
        <Card><p className="py-8 text-center text-sm text-slate-400">Click <b>Run attack chain</b> to execute the composed exploit against the local synthetic fixture.</p></Card>
      )}
      {act.busy && !result && (
        <Card><p className="py-8 text-center text-sm text-slate-400">Running the chain against four copies of the practice app…</p></Card>
      )}

      {original && (
        <div className="space-y-4">
          <Card title="Attack chain" actions={
            <Pill className={original.chain_succeeded ? "bg-rose-500/15 text-rose-300 ring-rose-500/40" : "bg-emerald-500/15 text-emerald-300 ring-emerald-500/40"}>
              {original.chain_succeeded ? "Full breach on the unpatched app" : "Chain blocked"}
            </Pill>}>
            <AttackGraph row={original} revealed={revealed} />
            <div className="mt-3 flex flex-wrap gap-3 text-xs text-slate-500">
              <span className="inline-flex items-center gap-1"><span className="h-2 w-2 rounded-full bg-rose-500" /> Breached</span>
              <span className="inline-flex items-center gap-1"><span className="h-2 w-2 rounded-full bg-emerald-500" /> Blocked</span>
              <span className="inline-flex items-center gap-1"><span className="h-2 w-2 rounded-full bg-slate-600" /> Unreachable</span>
            </div>
          </Card>

          <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_minmax(0,360px)]">
            <FixMatrix result={result!} />
            <BreachReceipt row={original} run={revealed >= original.steps.length} />
          </div>
        </div>
      )}
    </>
  );
}
