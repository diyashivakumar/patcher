import { Download, FileText, Printer } from "lucide-react";
import { Link, useParams } from "react-router-dom";
import { RunPhases, VerdictPanel } from "../components/RunView";
import { Button, ErrorBox, fmtDate, Loading, PageHeader, PatchStatusBadge, vulnLabel } from "../components/ui";
import { useApi } from "../hooks/useApi";
import { api } from "../services/api";

export function VerificationResult() {
  const { runId = "" } = useParams();
  const run = useApi(() => api.getRun(runId), [runId]);
  const r = run.data;

  if (run.loading && !r) return <Loading />;
  if (!r) return <ErrorBox error={run.error} onRetry={run.reload} />;
  const html = api.reportUrl(r.id, "html");
  const json = api.reportUrl(r.id, "json");

  const handlePrint = () => {
    window.print();
  };

  return (
    <>
      <PageHeader
        title={r.kind === "proof_of_fix" ? "Proof-of-Fix result" : "Baseline exploit replay"}
        subtitle={<>{vulnLabel(r.scenario)} · {fmtDate(r.created_at)}{r.patch_id && <> · <Link className="text-sky-400 hover:underline" to={`/patches/${r.patch_id}`}>View patch</Link></>}</>}
        actions={<div className="flex flex-wrap items-center gap-2 no-print">
          {r.patch_status && <PatchStatusBadge status={r.patch_status} />}
          <Button variant="secondary" onClick={handlePrint} className="gap-2">
            <Printer className="h-4 w-4" /> Print / Save as PDF
          </Button>
          {html && (
            <a
              className="inline-flex items-center gap-2 rounded-xl border border-slate-700/80 bg-slate-900 px-3.5 py-2 text-sm text-slate-200 transition hover:bg-slate-800"
              href={html}
              target="_blank"
              rel="noreferrer"
            >
              <FileText className="h-4 w-4 text-sky-400" /> HTML report
            </a>
          )}
          {json && (
            <a
              className="inline-flex items-center gap-2 rounded-xl border border-slate-700/80 bg-slate-900 px-3.5 py-2 text-sm text-slate-200 transition hover:bg-slate-800"
              href={json}
              target="_blank"
              rel="noreferrer"
            >
              <Download className="h-4 w-4 text-emerald-400" /> JSON
            </a>
          )}
        </div>}
      />
      <div className="space-y-4">
        <VerdictPanel run={r} />
        <RunPhases run={r} />
      </div>
    </>
  );
}
