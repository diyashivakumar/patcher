import { ChevronDown, ChevronRight, ShieldCheck, ShieldX } from "lucide-react";
import { useState } from "react";
import type { TestResult, VerificationRunDetail } from "../types/api";
import { Card, cx, Pill, TestStatus, VerdictBadge } from "./ui";

const PHASE_LABEL: Record<string, string> = {
  baseline: "Original code",
  before_patch: "Before patch (original code)",
  after_patch: "After patch (isolated patched copy)",
};

function Evidence({ result }: { result: TestResult }) {
  const req = result.evidence.request;
  const res = result.evidence.response;
  return (
    <div className="space-y-2 rounded-lg bg-slate-950 p-3 font-mono text-xs text-slate-300">
      {req && (
        <div>
          <span className="text-sky-400">{req.method}</span> {req.path}
          {Object.keys(req.params).length > 0 && (
            <span className="text-slate-500">
              {" "}
              ?{new URLSearchParams(req.params).toString()}
            </span>
          )}
          <span className="ml-2 text-slate-500">
            as <b className="text-slate-300">{req.actor}</b>
          </span>
        </div>
      )}
      {res && (
        <div>
          <div className="text-slate-500">HTTP {res.status_code} response:</div>
          <pre className="mt-1 max-h-48 overflow-auto whitespace-pre-wrap break-all text-slate-400">
            {res.body_excerpt || "(empty)"}
          </pre>
        </div>
      )}
      {result.evidence.traceback && (
        <pre className="whitespace-pre-wrap text-amber-300">
          {result.evidence.traceback}
        </pre>
      )}
    </div>
  );
}

function TestRow({ result }: { result: TestResult }) {
  const [open, setOpen] = useState(false);
  const pm = result.privilege_map;
  return (
    <>
      <tr
        className="cursor-pointer border-t border-slate-800 hover:bg-slate-800/40"
        onClick={() => setOpen(!open)}
      >
        <td className="py-2.5 pl-3 align-top text-slate-500">
          <button
            aria-label={`Evidence for ${result.name}`}
            aria-expanded={open}
            onClick={(event) => {
              event.stopPropagation();
              setOpen(!open);
            }}
          >
            {open ? (
              <ChevronDown className="h-4 w-4" />
            ) : (
              <ChevronRight className="h-4 w-4" />
            )}
          </button>
        </td>
        <td className="py-2.5 pr-3 align-top">
          <div className="text-slate-200">{result.name}</div>
          <div className="font-mono text-[11px] text-slate-500">
            {result.test_id}
          </div>
        </td>
        <td className="py-2.5 pr-3 align-top text-slate-400">
          {pm ? (
            <b className="text-slate-200">{pm.expected}</b>
          ) : (
            result.expected
          )}
        </td>
        <td className="py-2.5 pr-3 align-top text-slate-300">
          {result.exploit_succeeded && (
            <Pill className="mb-1 mr-1 bg-rose-500/15 text-rose-300 ring-rose-500/40">
              EXPLOITED
            </Pill>
          )}
          {result.actual}
        </td>
        <td className="py-2.5 pr-3 align-top">
          <TestStatus status={result.status} />
        </td>
      </tr>
      {open && (
        <tr>
          <td />
          <td colSpan={4} className="pb-3 pr-3">
            <p className="mb-2 text-xs text-slate-400">
              {result.description}
              {pm && ` — ${pm.reason}`}
            </p>
            <Evidence result={result} />
          </td>
        </tr>
      )}
    </>
  );
}

export function TestTable({
  results,
  empty = "No tests executed.",
}: {
  results: TestResult[];
  empty?: string;
}) {
  if (!results.length) return <p className="text-sm text-slate-500">{empty}</p>;
  return (
    <div className="overflow-x-auto">
      <table className="w-full min-w-[640px] text-left text-sm">
        <thead className="text-xs uppercase tracking-wide text-slate-500">
          <tr>
            <th className="w-8" />
            <th className="pb-2">Test</th>
            <th className="pb-2">Expected</th>
            <th className="pb-2">Observed</th>
            <th className="pb-2">Result</th>
          </tr>
        </thead>
        <tbody>
          {results.map((r) => (
            <TestRow key={`${r.phase}-${r.test_id}`} result={r} />
          ))}
        </tbody>
      </table>
    </div>
  );
}

function PhaseCard({
  run,
  phase,
}: {
  run: VerificationRunDetail;
  phase: string;
}) {
  const results = run.test_results.filter((t) => t.phase === phase);
  const summary = run.phase_summaries[phase];
  const security = results.filter((r) => r.category === "security");
  const regression = results.filter((r) => r.category === "regression");
  return (
    <Card
      title={PHASE_LABEL[phase] ?? phase}
      actions={
        summary &&
        (summary.exploit_reproduced ? (
          <Pill className="bg-rose-500/15 text-rose-300 ring-rose-500/40">
            <ShieldX className="h-3.5 w-3.5" />
            Exploit succeeded
          </Pill>
        ) : (
          <Pill className="bg-emerald-500/15 text-emerald-300 ring-emerald-500/40">
            <ShieldCheck className="h-3.5 w-3.5" />
            Exploit blocked
          </Pill>
        ))
      }
    >
      {summary?.load_error && (
        <p className="mb-3 text-sm text-rose-300">
          Application failed to load: {summary.load_error}
        </p>
      )}
      <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-slate-400">
        Security tests (exploits) · {summary?.security_tests.passed ?? 0}/
        {summary?.security_tests.total ?? 0} blocked
      </h3>
      <TestTable results={security} />
      <h3 className="mb-2 mt-5 text-xs font-semibold uppercase tracking-wide text-slate-400">
        Regression tests (legitimate use) ·{" "}
        {summary?.regression_tests.passed ?? 0}/
        {summary?.regression_tests.total ?? 0} passing
      </h3>
      <TestTable results={regression} />
    </Card>
  );
}

function Check({ ok, label }: { ok: boolean | null; label: string }) {
  return (
    <div
      className={cx(
        "flex items-center gap-2 rounded-lg border px-3 py-2 text-sm",
        ok
          ? "border-emerald-500/30 bg-emerald-500/5 text-emerald-200"
          : "border-rose-500/30 bg-rose-500/5 text-rose-200",
      )}
    >
      {ok ? (
        <ShieldCheck className="h-4 w-4" />
      ) : (
        <ShieldX className="h-4 w-4" />
      )}{" "}
      {label}
    </div>
  );
}

export function VerdictPanel({ run }: { run: VerificationRunDetail }) {
  if (run.kind === "baseline") {
    return (
      <Card title="Baseline exploit replay">
        <Check
          ok={!run.original_vulnerability_reproduced}
          label={
            run.original_vulnerability_reproduced
              ? "Vulnerability reproduced on the original code"
              : "Exploit did not succeed on the original code"
          }
        />
        {run.error && <p className="mt-3 text-sm text-rose-300">{run.error}</p>}
      </Card>
    );
  }
  return (
    <Card
      title="Proof-of-Fix verdict"
      actions={<VerdictBadge verdict={run.verdict} large />}
    >
      <div className="grid gap-2 sm:grid-cols-3">
        <Check
          ok={run.original_vulnerability_reproduced}
          label="Original exploit reproduced"
        />
        <Check
          ok={run.exploit_blocked_after_patch}
          label="Exploit blocked after patch"
        />
        <Check
          ok={run.regressions_pass_after_patch}
          label="Legitimate behaviour preserved"
        />
      </div>
      <ul className="mt-4 list-disc space-y-1 pl-5 text-sm text-slate-300">
        {run.verdict_reasons.map((r) => (
          <li key={r}>{r}</li>
        ))}
      </ul>
      {run.error && <p className="mt-3 text-sm text-rose-300">{run.error}</p>}
      <p className="mt-3 text-xs text-slate-500">
        Verdict computed deterministically from executed tests (
        {run.duration_ms ?? "?"} ms). No AI involved.
      </p>
    </Card>
  );
}

function Outcome({ result }: { result?: TestResult }) {
  if (!result) return <span className="text-slate-600">not run</span>;
  const label =
    result.category === "security"
      ? result.exploit_succeeded
        ? "Exploit succeeded"
        : result.status === "passed"
          ? "Exploit blocked"
          : "Failed"
      : result.status === "passed"
        ? "Works"
        : "Broken";
  const good = result.status === "passed";
  return (
    <div>
      <span
        className={cx(
          "inline-flex items-center gap-1 font-medium",
          good ? "text-emerald-400" : "text-rose-400",
        )}
      >
        {good ? (
          <ShieldCheck className="h-4 w-4" />
        ) : (
          <ShieldX className="h-4 w-4" />
        )}
        {label}
      </span>
      <div className="text-xs text-slate-500">{result.actual}</div>
    </div>
  );
}

/** Same test, before vs after the patch, row by row. Display only — the verdict comes from the runner. */
export function ExploitComparison({ run }: { run: VerificationRunDetail }) {
  const before = new Map(
    run.test_results
      .filter((t) => t.phase === "before_patch")
      .map((t) => [t.test_id, t]),
  );
  const after = new Map(
    run.test_results
      .filter((t) => t.phase === "after_patch")
      .map((t) => [t.test_id, t]),
  );
  const ids = [...new Set([...before.keys(), ...after.keys()])];
  if (!ids.length) return null;
  const section = (category: "security" | "regression", title: string) => {
    const rows = ids.filter(
      (id) => (before.get(id) ?? after.get(id))!.category === category,
    );
    return (
      <>
        <tr>
          <td
            colSpan={3}
            className="pb-1 pt-4 text-xs font-semibold uppercase tracking-wide text-slate-400"
          >
            {title}
          </td>
        </tr>
        {rows.map((id) => {
          const t = (after.get(id) ?? before.get(id))!;
          return (
            <tr key={id} className="border-t border-slate-800 align-top">
              <td className="py-2.5 pr-3">
                <div className="text-slate-200">{t.name}</div>
                {t.privilege_map && (
                  <div className="text-xs text-slate-500">
                    {t.privilege_map.actor} → {t.privilege_map.resource} ·
                    expected {t.privilege_map.expected}
                  </div>
                )}
              </td>
              <td className="py-2.5 pr-3">
                <Outcome result={before.get(id)} />
              </td>
              <td className="py-2.5">
                <Outcome result={after.get(id)} />
              </td>
            </tr>
          );
        })}
      </>
    );
  };
  return (
    <Card title="Same attack, before vs after the patch">
      <div className="overflow-x-auto">
        <table className="w-full min-w-[640px] text-left text-sm">
          <thead className="text-xs uppercase tracking-wide text-slate-500">
            <tr>
              <th className="w-2/5 pb-2">Test</th>
              <th className="pb-2">Before patch (original)</th>
              <th className="pb-2">After patch (isolated copy)</th>
            </tr>
          </thead>
          <tbody>
            {section(
              "security",
              "Exploit replay — must be blocked after the patch",
            )}
            {section(
              "regression",
              "Legitimate use — must keep working after the patch",
            )}
          </tbody>
        </table>
      </div>
    </Card>
  );
}

export function RunPhases({ run }: { run: VerificationRunDetail }) {
  const phases = ["baseline", "before_patch", "after_patch"].filter((p) =>
    run.test_results.some((t) => t.phase === p),
  );
  return (
    <div className={cx("grid gap-4", phases.length > 1 && "xl:grid-cols-2")}>
      {phases.map((p) => (
        <PhaseCard key={p} run={run} phase={p} />
      ))}
    </div>
  );
}
