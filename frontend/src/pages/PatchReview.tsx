import { AlertTriangle, CheckCircle2, RotateCcw, ShieldCheck, XCircle } from "lucide-react";
import { useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { CodeBlock, DiffView } from "../components/CodeBlock";
import { Button, Card, ErrorBox, fmtDate, Loading, PageHeader, PatchStatusBadge, strategyLabel, VerdictBadge, vulnLabel } from "../components/ui";
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
    const r = await action.run(() => api.rollbackPatch(p.id, p.status === "REJECTED" ? "Rejected by Proof-of-Fix" : "Manual rollback"));
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
        subtitle={<><Link className="text-sky-400 hover:underline" to={`/findings/${p.finding_id}`}>← Finding</Link> · {vulnLabel(p.vuln_type)} · {strategyLabel(p.strategy)}</>}
        actions={<PatchStatusBadge status={p.status} />}
      />
      {p.is_demo_bad_patch && (
        <div className="mb-4 flex gap-3 rounded-lg border border-amber-500/40 bg-amber-500/10 p-4 text-sm text-amber-200">
          <AlertTriangle className="h-5 w-5 shrink-0" />
          This is the deliberately over-restrictive demo patch. Static re-scanning thinks it is fine — run Proof-of-Fix to see
          PrivilegeMap catch it breaking legitimate users.
        </div>
      )}
      <div className="grid gap-4 xl:grid-cols-[minmax(0,1.5fr)_minmax(0,1fr)]">
        <div className="space-y-4">
          <Card title={`Unified diff · ${p.file_path}`}><DiffView diff={p.diff} /></Card>
          <div className="grid gap-4 lg:grid-cols-2">
            <Card title="Original"><CodeBlock code={p.original_snippet} startLine={p.line_start} /></Card>
            <Card title="Proposed"><CodeBlock code={p.patched_snippet} startLine={p.line_start} /></Card>
          </div>
        </div>
        <div className="space-y-4">
          <Card title="Why this patch">
            <p className="text-sm leading-relaxed text-slate-300">{p.rationale}</p>
            <h3 className="mb-2 mt-4 text-xs font-semibold uppercase tracking-wide text-slate-500">Static checks</h3>
            <ul className="space-y-1 text-sm">
              <li className="flex items-center gap-2">{p.validation.syntax_ok ? <CheckCircle2 className="h-4 w-4 text-emerald-400" /> : <XCircle className="h-4 w-4 text-rose-400" />}Patched file parses as valid Python</li>
              <li className="flex items-center gap-2">{p.validation.target_finding_cleared ? <CheckCircle2 className="h-4 w-4 text-emerald-400" /> : <XCircle className="h-4 w-4 text-rose-400" />}Scanner no longer reports this finding</li>
            </ul>
            <p className="mt-2 text-xs text-slate-500">{p.validation.note}</p>
          </Card>

          <Card title="Approval">
            {p.status === "PROPOSED" ? (
              <div className="space-y-3">
                <input className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm" placeholder="Your name (recorded in the audit log)"
                  value={approver} onChange={(e) => setApprover(e.target.value)} />
                <label className="flex items-start gap-2 text-sm text-slate-300">
                  <input type="checkbox" className="mt-1" checked={reviewed} onChange={(e) => setReviewed(e.target.checked)} />
                  I reviewed this diff and approve applying it to the project's working copy (a backup is kept).
                </label>
                <Button onClick={apply} busy={action.busy} disabled={!reviewed || !approver.trim()}>Approve & apply</Button>
              </div>
            ) : (
              <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 text-sm">
                <dt className="text-slate-500">Approved by</dt><dd>{p.approved_by ?? "—"}</dd>
                <dt className="text-slate-500">Applied</dt><dd>{fmtDate(p.applied_at)}</dd>
                {p.rolled_back_at && <><dt className="text-slate-500">Rolled back</dt><dd>{fmtDate(p.rolled_back_at)}</dd></>}
              </dl>
            )}
            {applied && (
              <div className="mt-4 flex flex-wrap gap-2">
                <Button onClick={verify} busy={action.busy}><ShieldCheck className="h-4 w-4" />Run Proof-of-Fix</Button>
                <Button variant="secondary" onClick={rollback} busy={action.busy}><RotateCcw className="h-4 w-4" />Roll back</Button>
              </div>
            )}
            <div className="mt-3"><ErrorBox error={action.error} /></div>
          </Card>

          {p.verification_runs.length > 0 && (
            <Card title="Verification history">
              <ul className="space-y-2 text-sm">
                {p.verification_runs.map((r) => (
                  <li key={r.id} className="flex items-center justify-between gap-2">
                    <Link className="text-sky-400 hover:underline" to={`/verification/${r.id}`}>{fmtDate(r.created_at)}</Link>
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
