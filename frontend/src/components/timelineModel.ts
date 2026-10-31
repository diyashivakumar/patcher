// Builds the Live Attack Timeline from REAL backend records only.
//
// The backend runs each step as one synchronous request and does not stream events,
// so the timeline is reconstructed from stored records. The only "running" state shown
// is the request the user has actually started and is still waiting on.
// Nothing here computes a verdict: stage 7 mirrors run.verdict from the testing runner.
import type { Patch, PhaseSummary, Severity, TestResult, VerificationRunDetail, VulnType } from "../types/api";

export type StageStatus = "pending" | "running" | "passed" | "failed" | "skipped" | "blocked" | "awaiting" | "partial";
export type StageKey = "reproduce" | "confirm" | "approve" | "apply" | "replay" | "regression" | "verdict";
/** A user action whose request is in flight (or just failed). */
export type InFlight = "baseline" | "scan" | "generate" | "apply" | "verify";

export interface TimelineFinding {
  id: string; vuln_type: VulnType; title: string; severity: Severity; cwe: string; confidence: string;
  file_path: string; line_start: number; line_end: number;
  recordedAt: string | null; // when the scan recorded it (finding.created_at or scan.started_at)
}

/** Patch fields the timeline uses. A full Patch satisfies this; a report's patch fills what it has. */
export type TimelinePatch = Pick<Patch, "id" | "strategy" | "status" | "approved_by" | "approved_at" | "diff"> &
  Partial<Pick<Patch, "applied_at" | "rolled_back_at" | "file_path" | "line_start" | "line_end" | "is_demo_bad_patch">>;

export interface TimelineInput {
  scenario: VulnType;
  baseline?: VerificationRunDetail | null; // Lab step 1 run (kind=baseline)
  finding?: TimelineFinding | null;
  patch?: TimelinePatch | null;
  proof?: VerificationRunDetail | null;    // kind=proof_of_fix
  running?: InFlight | null;
  failure?: { action: InFlight; message: string } | null;
}

export interface Timing { label: string; at?: string | null; durationMs?: number | null; note?: string }

export interface Stage {
  key: StageKey;
  title: string;
  status: StageStatus;
  summary: string;
  timing: Timing[];
  // Evidence payloads (only what exists). The UI decides how to render each.
  tests?: TestResult[];
  compare?: { before: TestResult | undefined; after: TestResult | undefined }[];
  phase?: PhaseSummary;
  facts?: [string, string][];
  diff?: string;
  reasons?: string[];
  error?: string;
}

const ACTION_STAGES: Record<InFlight, StageKey[]> = {
  baseline: ["reproduce"],
  scan: ["confirm"],
  generate: ["approve"],
  apply: ["apply"],
  verify: ["replay", "regression", "verdict"],
};

const byPhase = (run: VerificationRunDetail | null | undefined, phase: string) =>
  run?.test_results.filter((t) => t.phase === phase) ?? [];

function pairTests(proof: VerificationRunDetail, category: "security" | "regression") {
  const before = new Map(byPhase(proof, "before_patch").filter((t) => t.category === category).map((t) => [t.test_id, t]));
  const after = new Map(byPhase(proof, "after_patch").filter((t) => t.category === category).map((t) => [t.test_id, t]));
  return [...new Set([...before.keys(), ...after.keys()])].map((id) => ({ before: before.get(id), after: after.get(id) }));
}

export function buildTimeline(input: TimelineInput): Stage[] {
  const { baseline, finding, patch, proof, running, failure } = input;
  const runCompleted = proof?.status === "COMPLETED";
  const before = proof?.phase_summaries.before_patch;
  const after = proof?.phase_summaries.after_patch;
  const patchApplied = !!patch && ["APPLIED", "VERIFIED", "REJECTED"].includes(patch.status);
  const patchEverApplied = patchApplied || !!patch?.applied_at;

  // ---- 1. Exploit reproduction: the proof run's before-phase is authoritative; else the Lab's baseline run.
  let reproduce: Stage;
  if (proof && before) {
    const ok = !before.load_error && before.exploit_reproduced;
    reproduce = {
      key: "reproduce", title: "Exploit Reproduction", status: ok ? "passed" : "failed",
      summary: ok ? "The original exploit succeeded against the unpatched code (recorded in this verification run)."
        : before.load_error ? `The original application failed to load: ${before.load_error}`
        : "The exploit did not succeed against the original code, so the fix cannot be proven.",
      timing: [{ label: "Before-patch phase", durationMs: before.duration_ms }],
      tests: byPhase(proof, "before_patch").filter((t) => t.category === "security"), phase: before,
    };
  } else if (baseline) {
    const ok = baseline.status === "COMPLETED" && !!baseline.original_vulnerability_reproduced;
    reproduce = {
      key: "reproduce", title: "Exploit Reproduction", status: baseline.status === "ERROR" ? "failed" : ok ? "passed" : "failed",
      summary: baseline.status === "ERROR" ? `The runner could not execute: ${baseline.error}`
        : ok ? "The original exploit succeeded against the unpatched code." : "The exploit did not succeed against the original code.",
      timing: [{ label: "Baseline run", at: baseline.started_at, durationMs: baseline.duration_ms }],
      tests: byPhase(baseline, "baseline").filter((t) => t.category === "security"), phase: baseline.phase_summaries.baseline,
    };
  } else if (proof?.status === "ERROR") {
    reproduce = { key: "reproduce", title: "Exploit Reproduction", status: "skipped",
      summary: "Not executed: the verification run failed before the original exploit could be replayed.", timing: [] };
  } else {
    reproduce = { key: "reproduce", title: "Exploit Reproduction", status: "pending",
      summary: "Run the original exploit against the unpatched code.", timing: [] };
  }

  // ---- 2. Vulnerability confirmation: the scanner's stored finding.
  const confirm: Stage = finding ? {
    key: "confirm", title: "Vulnerability Confirmation", status: "passed",
    summary: `Static analysis located the ${finding.cwe} pattern at ${finding.file_path}:${finding.line_start}-${finding.line_end}.`,
    timing: finding.recordedAt ? [{ label: "Recorded by scan", at: finding.recordedAt }] : [],
    facts: [["Finding", finding.id], ["Title", finding.title], ["Category", finding.cwe], ["Severity", finding.severity],
      ["Confidence", finding.confidence], ["Location", `${finding.file_path}:${finding.line_start}-${finding.line_end}`]],
  } : { key: "confirm", title: "Vulnerability Confirmation", status: "pending",
    summary: "Scan the project source to locate the vulnerable code.", timing: [] };

  // ---- 3. Patch approval: a human must approve before anything is written.
  const approve: Stage = !patch
    ? { key: "approve", title: "Patch Approval", status: "pending", summary: "Generate a patch proposal to review.", timing: [] }
    : patch.status === "PROPOSED"
      ? { key: "approve", title: "Patch Approval", status: "awaiting",
          summary: "A patch proposal is ready. Nothing is applied until a named person approves it.", timing: [],
          facts: [["Patch", patch.id], ["Strategy", patch.strategy], ["Status", patch.status]], diff: patch.diff }
      : { key: "approve", title: "Patch Approval", status: "passed",
          summary: `Approved by ${patch.approved_by ?? "an unrecorded approver"}.`,
          timing: patch.approved_at ? [{ label: "Approved", at: patch.approved_at }] : [],
          facts: [["Patch", patch.id], ["Strategy", patch.strategy], ["Approved by", patch.approved_by ?? "—"]] };

  // ---- 4. Patch application (to the working copy; verification uses an isolated copy of it).
  let apply: Stage;
  if (!patch || patch.status === "PROPOSED") {
    apply = { key: "apply", title: "Patch Application", status: "pending", summary: "Waiting for approval.", timing: [] };
  } else {
    const rolledBack = patch.status === "ROLLED_BACK";
    apply = {
      key: "apply", title: "Patch Application", status: patchEverApplied ? "passed" : "pending",
      summary: rolledBack ? "The patch was applied and later rolled back; the original code was restored."
        : "Applied to the project's working copy after a backup. Verification runs on an isolated copy of it.",
      timing: [
        ...(patch.applied_at ? [{ label: "Applied", at: patch.applied_at }] : []),
        ...(patch.rolled_back_at ? [{ label: "Rolled back", at: patch.rolled_back_at }] : []),
      ],
      facts: [["Status", patch.status], ...(patch.file_path ? [["File changed", patch.line_start
        ? `${patch.file_path} (lines ${patch.line_start}-${patch.line_end})` : patch.file_path] as [string, string]] : [])],
      diff: patch.diff,
    };
  }

  // ---- 5–7 depend on the proof-of-fix run.
  const afterSec = byPhase(proof, "after_patch").filter((t) => t.category === "security");
  const afterReg = byPhase(proof, "after_patch").filter((t) => t.category === "regression");
  const notRun = (key: StageKey, title: string, why: string): Stage => ({ key, title, status: "skipped", summary: why, timing: [] });

  let replay: Stage, regression: Stage, verdict: Stage;
  if (proof && proof.status === "ERROR") {
    const why = "Not executed: the verification run failed before tests could run.";
    replay = notRun("replay", "Attack Replay", why);
    regression = notRun("regression", "Regression Testing", why);
    verdict = { key: "verdict", title: "Final Verdict", status: "failed", summary: "Verification could not be executed, so the patch is not validated.",
      timing: [{ label: "Run finished", at: proof.completed_at, durationMs: proof.duration_ms }], reasons: proof.verdict_reasons, error: proof.error ?? undefined };
  } else if (proof && runCompleted && after) {
    const g = proof.gauntlet;
    const bypasses = g?.counts.bypass ?? 0;
    const legitBroken = g?.counts.regression_failed ?? 0;
    const secOk = !after.load_error && after.security_tests.total > 0 && after.security_tests.failed + after.security_tests.errors === 0 && bypasses === 0;
    const regOk = !after.load_error && after.regression_tests.total > 0 && after.regression_tests.failed + after.regression_tests.errors === 0 && legitBroken === 0;
    const gauntletFacts: [string, string][] = g ? [["Variant Gauntlet", `${g.counts.blocked} blocked · ${bypasses} bypass · ${g.counts.invalid} invalid · ${g.counts.inconclusive} inconclusive`]] : [];
    const phaseTiming: Timing = { label: "After-patch phase", durationMs: after.duration_ms, note: "shared by replay and regression tests" };
    replay = {
      key: "replay", title: "Attack Replay", status: after.load_error ? "failed" : secOk ? "passed" : "failed",
      summary: after.load_error ? `The patched application failed to load: ${after.load_error}`
        : secOk ? `The same ${after.security_tests.total} exploit(s) were replayed and every one was blocked${g ? `, plus ${g.counts.blocked} Gauntlet variant(s)` : ""}.`
        : bypasses ? `${bypasses} exploit variant(s) bypass the patch (Exploit Variant Gauntlet).`
        : `${after.security_tests.failed + after.security_tests.errors} of ${after.security_tests.total} exploit(s) still succeed after the patch.`,
      timing: [phaseTiming], compare: pairTests(proof, "security"), tests: afterSec, phase: after, facts: gauntletFacts,
    };
    regression = after.load_error || after.regression_tests.total === 0
      ? notRun("regression", "Regression Testing", after.load_error ? "Not executed: the patched application did not load." : "No regression tests were executed.")
      : {
        key: "regression", title: "Regression Testing", status: regOk ? "passed" : "failed",
        summary: regOk ? `All ${after.regression_tests.total} legitimate-use checks still work after the patch.`
          : after.regression_tests.failed + after.regression_tests.errors
            ? `${after.regression_tests.failed + after.regression_tests.errors} of ${after.regression_tests.total} legitimate-use checks are broken by the patch.`
            : `${legitBroken} legitimate-use Gauntlet variant(s) are broken by the patch.`,
        timing: [phaseTiming], compare: pairTests(proof, "regression"), tests: afterReg, phase: after,
      };
    verdict = {
      key: "verdict", title: "Final Verdict",
      status: proof.verdict === "VERIFIED" ? "passed" : proof.verdict === "PARTIALLY_VERIFIED" ? "partial" : "failed",
      summary: proof.verdict === "VERIFIED" ? "VERIFIED — the exploit is blocked and legitimate behaviour is preserved."
        : proof.verdict === "PARTIALLY_VERIFIED" ? "PARTIALLY VERIFIED — all tests pass, but the original exploit was not reproduced."
        : "FAILED — the patch is rejected.",
      timing: [{ label: "Run finished", at: proof.completed_at, durationMs: proof.duration_ms, note: "whole verification request" }],
      reasons: proof.verdict_reasons,
    };
  } else {
    const blocked = patch?.status === "ROLLED_BACK" && !proof;
    const waitWhy = blocked ? "Blocked: the patch was rolled back, so there is nothing to replay against."
      : patchApplied ? "Ready: run Proof-of-Fix to replay the same attack on an isolated patched copy." : "Waiting for an applied patch.";
    replay = { key: "replay", title: "Attack Replay", status: blocked ? "blocked" : "pending", summary: waitWhy, timing: [] };
    regression = { key: "regression", title: "Regression Testing", status: blocked ? "blocked" : "pending",
      summary: blocked ? "Blocked: no applied patch to test." : "Legitimate-use checks run in the same verification request.", timing: [] };
    verdict = { key: "verdict", title: "Final Verdict", status: blocked ? "blocked" : "pending",
      summary: blocked ? "Blocked: no verification run exists for this patch." : "Decided by the testing runner from executed tests only.", timing: [] };
  }

  const stages = [reproduce, confirm, approve, apply, replay, regression, verdict];

  // Overlay the user's in-flight request (honest: we know the request is running, not its sub-steps).
  if (running) {
    for (const s of stages) if (ACTION_STAGES[running].includes(s.key)) {
      s.status = "running";
      s.summary = running === "verify"
        ? "Executing in one verification request; the runner does not report sub-step progress."
        : "Request in progress…";
    }
  }
  // Overlay a request that just failed with the backend's own error message.
  if (failure && !running) {
    for (const s of stages) if (ACTION_STAGES[failure.action][0] === s.key) {
      s.status = "failed";
      s.error = failure.message;
      s.summary = "The request failed; see the error below.";
    }
  }
  return stages;
}
