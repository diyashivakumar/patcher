import { ArrowRight, CheckCircle2, Play, RotateCcw, ShieldCheck, Sparkles, X } from "lucide-react";
import { useEffect, useState, type ReactNode } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { DiffView } from "../components/CodeBlock";
import { RunPhases, VerdictPanel } from "../components/RunView";
import { Button, Card, cx, ErrorBox, PageHeader, PatchStatusBadge, strategyLabel, vulnLabel } from "../components/ui";
import { useAction, useApi } from "../hooks/useApi";
import { api } from "../services/api";
import type { FindingDetail, Patch, VerificationRunDetail, VulnType } from "../types/api";

const selectCls =
  "rounded-lg border border-slate-700/80 bg-slate-900/90 px-3 py-2 text-xs sm:text-sm text-slate-100 transition focus:border-sky-500 focus:outline-none focus:ring-1 focus:ring-sky-500/20";

const inputCls =
  "rounded-lg border border-slate-700/80 bg-slate-900/90 px-3 py-2 text-xs sm:text-sm text-slate-100 placeholder:text-slate-500 transition focus:border-sky-500 focus:outline-none focus:ring-1 focus:ring-sky-500/20";

function StepBadge({ n, done, active }: { n: number; done: boolean; active: boolean }) {
  if (done) return (
    <span className="flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
      <CheckCircle2 className="h-3.5 w-3.5" />
    </span>
  );
  if (active) return (
    <span className="flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-sky-500 text-slate-950 text-xs font-bold shadow-sm">
      {n}
    </span>
  );
  return (
    <span className="flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-slate-800/80 border border-slate-700/60 text-slate-500 text-xs font-semibold">
      {n}
    </span>
  );
}

function Step({ n, title, done, active, children }: { n: number; title: string; done: boolean; active: boolean; children: ReactNode }) {
  return (
    <section
      className={cx(
        "rounded-xl border p-5 transition-all duration-200",
        active
          ? "border-sky-500/30 bg-[#10141d]/90 shadow-sm"
          : done
          ? "border-emerald-500/20 bg-[#10141d]/50"
          : "border-slate-800/60 bg-[#10141d]/30 opacity-70"
      )}
    >
      <div className="mb-4 flex items-center gap-3">
        <StepBadge n={n} done={done} active={active} />
        <h2 className={cx("text-sm font-semibold tracking-tight", active ? "text-white" : done ? "text-slate-200" : "text-slate-400")}>
          {title}
        </h2>
        {done && !active && (
          <span className="ml-auto rounded-md bg-emerald-500/10 px-2 py-0.5 text-xs font-medium text-emerald-400 border border-emerald-500/20">
            Completed
          </span>
        )}
      </div>
      {(active || done) && <div className="animate-fade-in">{children}</div>}
    </section>
  );
}

export function AttackReplayLab() {
  const [params, setParams] = useSearchParams();
  const projects = useApi(() => api.listProjects());
  const act = useAction();
  const verifiable = projects.data?.filter((p) => p.verification_supported) ?? [];
  const projectId = params.get("project") ?? "";
  const scenario = (params.get("scenario") as VulnType) || "sqli";

  const [baseline, setBaseline] = useState<VerificationRunDetail | null>(null);
  const [finding, setFinding] = useState<FindingDetail | null>(null);
  const [strategy, setStrategy] = useState("");
  const [patch, setPatch] = useState<Patch | null>(null);
  const [approver, setApprover] = useState("");
  const [proof, setProof] = useState<VerificationRunDetail | null>(null);
  const [notice, setNotice] = useState("");

  useEffect(() => {
    if (!projectId && verifiable.length) setParams({ project: verifiable[0].id, scenario }, { replace: true });
  }, [projectId, verifiable, scenario, setParams]);

  const reset = () => { setBaseline(null); setFinding(null); setPatch(null); setProof(null); setNotice(""); act.clearError(); };
  useEffect(() => { reset(); setStrategy(scenario === "sqli" ? "parameterized_query" : "ownership_check"); }, [projectId, scenario]);

  const createFresh = () => act.run(async () => {
    const p = await api.createProject({ name: "Attack Replay demo", description: "Fresh copy for the Attack Replay Lab", fixture_name: "student_portal" });
    await projects.reload();
    setParams({ project: p.id, scenario });
  });

  const runBaseline = () => act.run(async () => setBaseline(await api.runBaseline(projectId, scenario)));

  const locateFinding = () => act.run(async () => {
    setNotice("");
    const scan = await api.runScan(projectId);
    const found = (await api.getScanFindings(scan.id)).find((f) => f.vuln_type === scenario);
    if (!found) {
      setNotice(`The latest scan reports no ${vulnLabel(scenario)} finding. This project's working copy may already be patched — create a fresh demo project.`);
      return;
    }
    const detail = await api.getFinding(found.id);
    setFinding(detail);
    const active = detail.patches.find((p) => ["APPLIED", "VERIFIED", "REJECTED"].includes(p.status));
    if (active) {
      setNotice("Scan still flags the original code, but an earlier patch for an older scan is applied. Loaded it.");
      setPatch(await api.getPatch(active.id));
    }
  });

  const generate = () => act.run(async () => finding && setPatch(await api.generatePatch(finding.id, strategy)));
  const apply = () => act.run(async () => patch && setPatch(await api.applyPatch(patch.id, approver.trim())));
  const replay = () => act.run(async () => {
    if (!patch) return;
    const run = await api.runProofOfFix(patch.id);
    setProof(run);
    setPatch(await api.getPatch(patch.id));
  });
  const rollbackAndRetry = () => act.run(async () => {
    if (!patch) return;
    await api.rollbackPatch(patch.id, "Rejected by Proof-of-Fix in Attack Replay Lab");
    setPatch(null);
    setProof(null);
    setStrategy(scenario === "sqli" ? "parameterized_query" : "ownership_check");
  });

  const applied = !!patch && patch.status !== "PROPOSED" && patch.status !== "ROLLED_BACK";
  const step = !baseline ? 1 : !finding ? 2 : !patch ? 3 : !applied ? 4 : !proof ? 5 : 6;

  // Progress bar percentage
  const progress = Math.round(((step - 1) / 5) * 100);

  return (
    <>
      <PageHeader
        title="Attack Replay Lab"
        subtitle="Reproduce a real exploit, patch it, then replay the same attack to prove the fix works. All results are executed — not simulated."
      />

      {/* Config card */}
      <Card className="mb-6 animate-fade-in">
        <div className="flex flex-wrap items-end gap-4">
          <label className="flex flex-col gap-1.5">
            <span className="text-[11px] font-semibold uppercase tracking-widest text-slate-500">Project</span>
            <select
              className={selectCls}
              value={projectId}
              onChange={(e) => setParams({ project: e.target.value, scenario })}
            >
              {!verifiable.length && <option value="">No fixture projects yet</option>}
              {verifiable.map((p) => (
                <option key={p.id} value={p.id}>{p.name} ({p.id.slice(0, 8)})</option>
              ))}
            </select>
          </label>
          <label className="flex flex-col gap-1.5">
            <span className="text-[11px] font-semibold uppercase tracking-widest text-slate-500">Vulnerability</span>
            <select
              className={selectCls}
              value={scenario}
              onChange={(e) => setParams({ project: projectId, scenario: e.target.value })}
            >
              <option value="sqli">SQL Injection</option>
              <option value="idor">Broken Access Control (IDOR)</option>
            </select>
          </label>
          <Button variant="secondary" onClick={createFresh} busy={act.busy}>
            <Sparkles className="h-4 w-4" /> New fresh demo project
          </Button>
          {(baseline || finding) && (
            <Button variant="ghost" onClick={reset} className="text-slate-500">
              <X className="h-4 w-4" /> Reset steps
            </Button>
          )}
        </div>

        {/* Progress bar */}
        {projectId && (
          <div className="mt-5">
            <div className="mb-1.5 flex items-center justify-between">
              <span className="text-xs text-slate-500">Progress</span>
              <span className="text-xs font-semibold text-sky-400">Step {step} of 5</span>
            </div>
            <div className="h-1.5 overflow-hidden rounded-full bg-slate-800">
              <div
                className="h-full rounded-full bg-gradient-to-r from-sky-500 to-indigo-500 transition-all duration-500"
                style={{ width: `${progress}%` }}
              />
            </div>
          </div>
        )}
      </Card>

      <ErrorBox error={act.error} />
      {notice && (
        <div className="mb-4 flex items-start gap-3 rounded-xl border border-amber-500/30 bg-amber-500/8 p-4 text-sm text-amber-200">
          <span className="mt-0.5 h-4 w-4 shrink-0 text-amber-400">⚠</span>
          <span>{notice}</span>
        </div>
      )}

      {projectId && (
        <div className="space-y-3">
          {/* Step 1 */}
          <Step n={1} title="Run the original exploit" done={!!baseline} active={step === 1}>
            {!baseline ? (
              <Button onClick={runBaseline} busy={act.busy}>
                <Play className="h-4 w-4" /> Run {vulnLabel(scenario)} exploit on original code
              </Button>
            ) : (
              <div className="space-y-4">
                <VerdictPanel run={baseline} />
                <RunPhases run={baseline} />
                <button onClick={() => {}} className="inline-flex items-center gap-1.5 text-sm text-sky-400 hover:underline">
                  Continue to next step <ArrowRight className="h-3.5 w-3.5" />
                </button>
              </div>
            )}
          </Step>

          {/* Step 2 */}
          <Step n={2} title="Locate the vulnerable code" done={!!finding} active={step === 2}>
            {!finding ? (
              <Button onClick={locateFinding} busy={act.busy}>
                Scan project source
              </Button>
            ) : (
              <p className="text-sm text-slate-300 leading-relaxed">
                Found at{" "}
                <code className="rounded-md bg-slate-800 px-1.5 py-0.5 text-sky-300">
                  {finding.file_path}:{finding.line_start}-{finding.line_end}
                </code>{" "}
                ·{" "}
                <Link className="text-sky-400 hover:underline" to={`/findings/${finding.id}`}>
                  full finding details
                </Link>
              </p>
            )}
          </Step>

          {/* Step 3 */}
          <Step n={3} title="Review the proposed patch" done={!!patch} active={step === 3}>
            {!patch && finding ? (
              <div className="flex flex-wrap items-center gap-3">
                <select className={selectCls} value={strategy} onChange={(e) => setStrategy(e.target.value)}>
                  {finding.available_strategies.map((s) => (
                    <option key={s} value={s}>{strategyLabel(s)}</option>
                  ))}
                </select>
                <Button onClick={generate} busy={act.busy}>Generate patch</Button>
              </div>
            ) : patch && (
              <div className="space-y-3">
                <div className="flex items-center gap-2 text-sm">
                  <PatchStatusBadge status={patch.status} />
                  <span className="text-slate-300">{strategyLabel(patch.strategy)}</span>
                </div>
                <p className="text-sm text-slate-400 leading-relaxed">{patch.rationale}</p>
                <DiffView diff={patch.diff} />
              </div>
            )}
          </Step>

          {/* Step 4 */}
          <Step n={4} title="Approve and apply" done={applied} active={step === 4}>
            {patch?.status === "PROPOSED" ? (
              <div className="flex flex-wrap items-center gap-3">
                <input
                  className={inputCls}
                  placeholder="Your name (recorded in audit log)"
                  value={approver}
                  onChange={(e) => setApprover(e.target.value)}
                />
                <Button onClick={apply} busy={act.busy} disabled={!approver.trim()}>
                  Approve & apply to working copy
                </Button>
              </div>
            ) : patch && (
              <p className="text-sm text-slate-300">
                Applied by <span className="font-semibold text-white">{patch.approved_by}</span>.{" "}
                Original file backed up.
              </p>
            )}
          </Step>

          {/* Step 5 */}
          <Step n={5} title="Replay the same attack + regression tests" done={!!proof} active={step === 5}>
            {!proof ? (
              <Button onClick={replay} busy={act.busy}>
                <ShieldCheck className="h-4 w-4" /> Run Proof-of-Fix
              </Button>
            ) : (
              <div className="space-y-4">
                <VerdictPanel run={proof} />
                {proof.verdict !== "VERIFIED" && patch && ["REJECTED", "APPLIED"].includes(patch.status) && (
                  <Button variant="danger" onClick={rollbackAndRetry} busy={act.busy}>
                    <RotateCcw className="h-4 w-4" /> Roll back this patch and try another
                  </Button>
                )}
                <RunPhases run={proof} />
                <Link
                  className="inline-flex items-center gap-1.5 text-sm text-sky-400 hover:underline"
                  to={`/verification/${proof.id}`}
                >
                  Open full verification report <ArrowRight className="h-3.5 w-3.5" />
                </Link>
              </div>
            )}
          </Step>
        </div>
      )}
    </>
  );
}
