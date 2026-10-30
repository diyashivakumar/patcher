import { AlertTriangle, ArrowLeft, CheckCircle2, History, RotateCcw, ShieldCheck, XCircle } from "lucide-react";
import { useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { CodeBlock, DiffView } from "../components/CodeBlock";
import {
  Button,
  Card,
  ErrorBox,
  fmtDate,
  Loading,
  PageHeader,
  PatchStatusBadge,
  strategyLabel,
  VerdictBadge,
  vulnLabel,
} from "../components/ui";
import { useAction, useApi } from "../hooks/useApi";
import { api } from "../services/api";

export function PatchReview() {
  const { patchId = "" } = useParams();
  const patch = useApi(() => api.getPatch(patchId), [patchId]);
  const action = useAction();
  const navigate = useNavigate();
  const [approver, setApprover] = useState("");
  const [reviewed, setReviewed] = useState(false);
  const p = patch.data;

  if (patch.loading && !p) return <Loading />;
  if (!p) return <ErrorBox error={patch.error} onRetry={patch.reload} />;

  const apply = async () => {
    const r = await action.run(() => api.applyPatch(p.id, approver.trim()));
    if (r) patch.setData(r);
  };
  const rollback = async () => {
    const r = await action.run(() =>
      api.rollbackPatch(p.id, p.status === "REJECTED" ? "Rejected by Proof-of-Fix" : "Manual rollback")
    );
    if (r) patch.setData(r);
  };
  const verify = async () => {
    const run = await action.run(() => api.runProofOfFix(p.id));
    if (run) navigate(`/verification/${run.id}`);
  };
  const applied = ["APPLIED", "VERIFIED", "REJECTED"].includes(p.status);

  return (
    <>
      <PageHeader
        title="Patch review"
        subtitle={
          <>
            <Link
              className="inline-flex items-center gap-1 text-sky-400 hover:underline"
              to={`/findings/${p.finding_id}`}
            >
              <ArrowLeft className="h-3.5 w-3.5" /> Finding
            </Link>
            <span className="mx-2 text-slate-600">·</span>
            {vulnLabel(p.vuln_type)}
            <span className="mx-2 text-slate-600">·</span>
            {strategyLabel(p.strategy)}
          </>
        }
        actions={<PatchStatusBadge status={p.status} />}
      />

      {p.is_demo_bad_patch && (
        <div className="mb-5 flex gap-3 rounded-2xl border border-amber-500/30 bg-amber-500/8 p-4 text-sm text-amber-200">
          <AlertTriangle className="h-5 w-5 shrink-0 text-amber-400" />
          <p className="leading-relaxed">
            This is the deliberately over-restrictive demo patch. Static re-scanning thinks it is fine — run{" "}
            <strong>Proof-of-Fix</strong> to see PrivilegeMap catch it breaking legitimate users.
          </p>
        </div>
      )}

      <div className="grid gap-5 xl:grid-cols-[1.5fr_1fr]">
        {/* Left: code */}
        <div className="space-y-5">
          <Card title={<span className="font-mono text-xs">Unified diff · {p.file_path}</span>}>
            <DiffView diff={p.diff} />
          </Card>
          <div className="grid gap-4 lg:grid-cols-2">
            <Card title="Original">
              <CodeBlock code={p.original_snippet} startLine={p.line_start} />
            </Card>
            <Card title="Proposed">
              <CodeBlock code={p.patched_snippet} startLine={p.line_start} />
            </Card>
          </div>
        </div>

        {/* Right: review */}
        <div className="space-y-5">
          {/* Why this patch */}
          <Card title="Why this patch">
            <p className="text-sm leading-relaxed text-slate-300">{p.rationale}</p>
            <h3 className="mb-3 mt-5 text-[10px] font-bold uppercase tracking-widest text-slate-500">
              Static checks
            </h3>
            <ul className="space-y-2">
              <li
                className={`flex items-center gap-3 rounded-xl border px-3.5 py-2.5 text-sm ${
                  p.validation.syntax_ok
                    ? "border-emerald-500/20 bg-emerald-500/5 text-emerald-200"
                    : "border-rose-500/20 bg-rose-500/5 text-rose-200"
                }`}
              >
                {p.validation.syntax_ok ? (
                  <CheckCircle2 className="h-4 w-4 shrink-0 text-emerald-400" />
                ) : (
                  <XCircle className="h-4 w-4 shrink-0 text-rose-400" />
                )}
                Patched file parses as valid Python
              </li>
              <li
                className={`flex items-center gap-3 rounded-xl border px-3.5 py-2.5 text-sm ${
                  p.validation.target_finding_cleared
                    ? "border-emerald-500/20 bg-emerald-500/5 text-emerald-200"
                    : "border-rose-500/20 bg-rose-500/5 text-rose-200"
                }`}
              >
                {p.validation.target_finding_cleared ? (
                  <CheckCircle2 className="h-4 w-4 shrink-0 text-emerald-400" />
                ) : (
                  <XCircle className="h-4 w-4 shrink-0 text-rose-400" />
                )}
                Scanner no longer reports this finding
              </li>
            </ul>
            {p.validation.note && (
              <p className="mt-3 text-xs text-slate-500 leading-relaxed">{p.validation.note}</p>
            )}
          </Card>

          {/* Approval */}
          <Card title="Approval">
            {p.status === "PROPOSED" ? (
              <div className="space-y-4">
                <div>
                  <label className="mb-1.5 block text-[10px] font-bold uppercase tracking-widest text-slate-500">
                    Your name
                  </label>
                  <input
                    className="w-full rounded-xl border border-slate-700/80 bg-slate-900 px-3.5 py-2.5 text-sm text-slate-100 placeholder:text-slate-600 transition focus:border-sky-500 focus:outline-none focus:ring-2 focus:ring-sky-500/20"
                    placeholder="Recorded in the audit log"
                    value={approver}
                    onChange={(e) => setApprover(e.target.value)}
                  />
                </div>
                <label className="flex items-start gap-3 cursor-pointer">
                  <div className="relative mt-0.5">
                    <input
                      type="checkbox"
                      className="peer sr-only"
                      checked={reviewed}
                      onChange={(e) => setReviewed(e.target.checked)}
                    />
                    <div className="h-4 w-4 rounded border border-slate-600 bg-slate-800 transition peer-checked:border-sky-500 peer-checked:bg-sky-500" />
                    {reviewed && (
                      <CheckCircle2 className="absolute inset-0 h-4 w-4 text-slate-950" />
                    )}
                  </div>
                  <span className="text-sm text-slate-300 leading-relaxed">
                    I reviewed this diff and approve applying it to the project's working copy (a backup is kept).
                  </span>
                </label>
                <Button
                  onClick={apply}
                  busy={action.busy}
                  disabled={!reviewed || !approver.trim()}
                  className="w-full justify-center"
                >
                  <ShieldCheck className="h-4 w-4" /> Approve & apply
                </Button>
              </div>
            ) : (
              <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-2.5 text-sm">
                <dt className="text-slate-500">Approved by</dt>
                <dd className="font-medium text-slate-200">{p.approved_by ?? "—"}</dd>
                <dt className="text-slate-500">Applied</dt>
                <dd className="tabular-nums text-slate-400 text-xs">{fmtDate(p.applied_at)}</dd>
                {p.rolled_back_at && (
                  <>
                    <dt className="text-slate-500">Rolled back</dt>
                    <dd className="tabular-nums text-slate-400 text-xs">{fmtDate(p.rolled_back_at)}</dd>
                  </>
                )}
              </dl>
            )}

            {applied && (
              <div className="mt-4 flex flex-wrap gap-2">
                <Button onClick={verify} busy={action.busy}>
                  <ShieldCheck className="h-4 w-4" /> Run Proof-of-Fix
                </Button>
                <Button variant="secondary" onClick={rollback} busy={action.busy}>
                  <RotateCcw className="h-4 w-4" /> Roll back
                </Button>
              </div>
            )}
            <div className="mt-3">
              <ErrorBox error={action.error} />
            </div>
          </Card>

          {/* Verification history */}
          {p.verification_runs.length > 0 && (
            <Card
              title={
                <span className="inline-flex items-center gap-2">
                  <History className="h-4 w-4 text-sky-400" />
                  Verification history
                </span>
              }
            >
              <ul className="space-y-2">
                {p.verification_runs.map((r) => (
                  <li
                    key={r.id}
                    className="flex items-center justify-between gap-2 rounded-xl border border-slate-800/60 bg-slate-950/40 px-3.5 py-2.5"
                  >
                    <Link
                      className="text-sm text-sky-400 hover:underline tabular-nums"
                      to={`/verification/${r.id}`}
                    >
                      {fmtDate(r.created_at)}
                    </Link>
                    <VerdictBadge verdict={r.verdict} />
                  </li>
                ))}
              </ul>
            </Card>
          )}
        </div>
      </div>
    </>
  );
}
