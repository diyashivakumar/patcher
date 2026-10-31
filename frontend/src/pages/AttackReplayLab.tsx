import { AlertTriangle, CheckCircle2, Circle, Play, RotateCcw, ShieldCheck, Sparkles, XCircle } from "lucide-react";
import { useEffect, useState, type ReactNode } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { AttackTimeline } from "../components/AttackTimeline";
import { DiffView } from "../components/CodeBlock";
import { GauntletSummaryCard } from "../components/GauntletParts";
import type { InFlight } from "../components/timelineModel";
import { ExploitComparison, RunPhases, VerdictPanel } from "../components/RunView";
import { Button, Card, cx, ErrorBox, PageHeader, PatchStatusBadge, strategyLabel, vulnLabel } from "../components/ui";
import { useAction, useApi } from "../hooks/useApi";
import { api } from "../services/api";
import type { FindingDetail, Patch, Verdict, VerificationRunDetail, VulnType } from "../types/api";

const select = "rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100";

// The final step's icon mirrors the backend verdict, so a FAILED run never shows a green tick.
const VERDICT_ICON: Record<Verdict, ReactNode> = {
  VERIFIED: <CheckCircle2 className="h-5 w-5 text-emerald-400" />,
  PARTIALLY_VERIFIED: <AlertTriangle className="h-5 w-5 text-amber-400" />,
  FAILED: <XCircle className="h-5 w-5 text-rose-400" />,
};

function Step({ n, stage, title, done, active, verdict, children }: {
  n: number; stage: string; title: string; done: boolean; active: boolean; verdict?: Verdict | null; children: ReactNode;
}) {
  return (
    <section className={cx("rounded-xl border p-5", active ? "border-sky-500/50 bg-slate-900" : "border-slate-800 bg-slate-900/40")}>
      <h2 className="mb-3 flex items-center gap-2 text-sm font-semibold text-slate-200">
        {done && verdict ? VERDICT_ICON[verdict] : done ? <CheckCircle2 className="h-5 w-5 text-emerald-400" /> : <Circle className={cx("h-5 w-5", active ? "text-sky-400" : "text-slate-600")} />}
        <span className="text-xs font-semibold uppercase tracking-wider text-sky-400/80">{stage}</span>
        <span className="text-slate-500">·</span> Step {n} · {title}
      </h2>
      {(active || done) && children}
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
  // Which request is actually in flight (or just failed) -- drives the timeline's Running/Failed overlay.
  const [inFlight, setInFlight] = useState<InFlight | null>(null);
  const [failure, setFailure] = useState<{ action: InFlight; message: string } | null>(null);

  const track = (action: InFlight, fn: () => Promise<unknown>) => act.run(async () => {
    setInFlight(action);
    setFailure(null);
    try {
      await fn();
    } catch (e) {
      setFailure({ action, message: (e as Error).message });
      throw e; // still surfaced by act.error / ErrorBox
    } finally {
      setInFlight(null);
    }
  });

  useEffect(() => {
    if (!projectId && verifiable.length) setParams({ project: verifiable[0].id, scenario }, { replace: true });
  }, [projectId, verifiable, scenario, setParams]);

  const reset = () => { setBaseline(null); setFinding(null); setPatch(null); setProof(null); setNotice(""); setFailure(null); act.clearError(); };
  // Reset the walkthrough whenever the project or vulnerability changes.
  useEffect(() => { reset(); setStrategy(scenario === "sqli" ? "parameterized_query" : "ownership_check"); }, [projectId, scenario]);

  const createFresh = () => act.run(async () => {
    const p = await api.createProject({ name: "Attack Replay demo", description: "Fresh copy for the Attack Replay Lab", fixture_name: "student_portal" });
    await projects.reload();
    setParams({ project: p.id, scenario });
  });

  const runBaseline = () => track("baseline", async () => setBaseline(await api.runBaseline(projectId, scenario)));

  const locateFinding = () => track("scan", async () => {
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

  const generate = () => track("generate", async () => finding && setPatch(await api.generatePatch(finding.id, strategy)));
  const apply = () => track("apply", async () => patch && setPatch(await api.applyPatch(patch.id, approver.trim())));
  const replay = () => track("verify", async () => {
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
    setFailure(null);
    setStrategy(scenario === "sqli" ? "parameterized_query" : "ownership_check");
  });

  const applied = !!patch && patch.status !== "PROPOSED" && patch.status !== "ROLLED_BACK";
  const step = !baseline ? 1 : !finding ? 2 : !patch ? 3 : !applied ? 4 : !proof ? 5 : 6;

  return (
    <>
      <PageHeader
        title="Attack Replay Lab"
        subtitle="Reproduce a real exploit against the local practice app, patch it, and replay the same attack. All results are executed, not simulated."
      />
      <Card className="mb-4">
        <div className="flex flex-wrap items-end gap-3">
          <label className="text-xs text-slate-400">Project<br />
            <select className={select} value={projectId} onChange={(e) => setParams({ project: e.target.value, scenario })}>
              {!verifiable.length && <option value="">No fixture projects yet</option>}
              {verifiable.map((p) => <option key={p.id} value={p.id}>{p.name} ({p.id.slice(0, 8)})</option>)}
            </select>
          </label>
          <label className="text-xs text-slate-400">Vulnerability<br />
            <select className={select} value={scenario} onChange={(e) => setParams({ project: projectId, scenario: e.target.value })}>
              <option value="sqli">SQL Injection</option>
              <option value="idor">Broken Access Control (IDOR)</option>
            </select>
          </label>
          <Button variant="secondary" onClick={createFresh} busy={act.busy}><Sparkles className="h-4 w-4" />New fresh demo project</Button>
          {(baseline || finding) && <Button variant="ghost" onClick={reset}>Restart steps</Button>}
        </div>
      </Card>
      <ErrorBox error={act.error} />
      {notice && <div className="mb-4 rounded-lg border border-amber-500/40 bg-amber-500/10 p-3 text-sm text-amber-200">{notice}</div>}

      {projectId && (
        <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_minmax(0,460px)]">
        <aside className="xl:order-2">
          <div className="xl:sticky xl:top-4 xl:max-h-[calc(100vh-2rem)] xl:overflow-y-auto">
            <AttackTimeline
              scenario={scenario}
              baseline={baseline}
              finding={finding && { ...finding, recordedAt: finding.created_at }}
              patch={patch}
              proof={proof}
              running={inFlight}
              failure={failure}
            />
          </div>
        </aside>
        <div className="space-y-4 xl:order-1">
          <Step n={1} stage="Before patch" title="Run the original exploit" done={!!baseline} active={step === 1}>
            {!baseline ? (
              <Button onClick={runBaseline} busy={act.busy}><Play className="h-4 w-4" />Run {vulnLabel(scenario)} exploit on original code</Button>
            ) : (
              <div className="space-y-4"><VerdictPanel run={baseline} /><RunPhases run={baseline} /></div>
            )}
          </Step>

          <Step n={2} stage="Before patch" title="Locate the vulnerable code" done={!!finding} active={step === 2}>
            {!finding ? <Button onClick={locateFinding} busy={act.busy}>Scan project source</Button> : (
              <p className="text-sm text-slate-300">
                Found at <code className="text-sky-300">{finding.file_path}:{finding.line_start}-{finding.line_end}</code> ·{" "}
                <Link className="text-sky-400 hover:underline" to={`/findings/${finding.id}`}>full finding details</Link>
              </p>
            )}
          </Step>

          <Step n={3} stage="Patch" title="Review the proposed patch" done={!!patch} active={step === 3}>
            {!patch && finding ? (
              <div className="flex flex-wrap items-center gap-3">
                <select className={select} value={strategy} onChange={(e) => setStrategy(e.target.value)}>
                  {finding.available_strategies.map((s) => <option key={s} value={s}>{strategyLabel(s)}</option>)}
                </select>
                <Button onClick={generate} busy={act.busy}>Generate patch</Button>
              </div>
            ) : patch && (
              <div className="space-y-3">
                <div className="flex items-center gap-2 text-sm"><PatchStatusBadge status={patch.status} /> {strategyLabel(patch.strategy)}</div>
                <p className="text-sm text-slate-400">{patch.rationale}</p>
                <DiffView diff={patch.diff} />
              </div>
            )}
          </Step>

          <Step n={4} stage="Patch" title="Approve and apply" done={applied} active={step === 4}>
            {patch?.status === "PROPOSED" ? (
              <div className="flex flex-wrap items-center gap-3">
                <input className={select} placeholder="Approver name" value={approver} onChange={(e) => setApprover(e.target.value)} />
                <Button onClick={apply} busy={act.busy} disabled={!approver.trim()}>Approve & apply to working copy</Button>
              </div>
            ) : patch && <p className="text-sm text-slate-300">Applied by {patch.approved_by}. Original file backed up.</p>}
          </Step>

          <Step n={5} stage="After patch" title="Replay the same attack + regression tests" done={!!proof} active={step === 5}>
            {!proof ? <Button onClick={replay} busy={act.busy}><ShieldCheck className="h-4 w-4" />Run Proof-of-Fix</Button> : (
              <div className="space-y-4">
                <GauntletSummaryCard run={proof} />
                <ExploitComparison run={proof} />
                <details className="rounded-xl border border-slate-800 bg-slate-900/40 p-4">
                  <summary className="cursor-pointer text-sm text-slate-300">Full test evidence (requests and responses for both phases)</summary>
                  <div className="mt-4"><RunPhases run={proof} /></div>
                </details>
              </div>
            )}
          </Step>

          <Step n={6} stage="Final verdict" title="Was the fix proven?" done={!!proof} active={false} verdict={proof?.verdict}>
            {proof && (
              <div className="space-y-4">
                <VerdictPanel run={proof} />
                {proof.verdict === "FAILED" && proof.exploit_blocked_after_patch && proof.regressions_pass_after_patch === false && (
                  <p className="text-sm text-rose-200">The attack was blocked, but legitimate users lost access, so this patch is rejected. Blocking the exploit alone is not enough.</p>
                )}
                <div className="flex flex-wrap items-center gap-3">
                  {proof.verdict !== "VERIFIED" && patch && ["REJECTED", "APPLIED"].includes(patch.status) && (
                    <Button variant="danger" onClick={rollbackAndRetry} busy={act.busy}><RotateCcw className="h-4 w-4" />Roll back this patch and try another</Button>
                  )}
                  <Link className="text-sm text-sky-400 hover:underline" to={`/verification/${proof.id}`}>Open verification report →</Link>
                </div>
              </div>
            )}
          </Step>
        </div>
        </div>
      )}
    </>
  );
}
