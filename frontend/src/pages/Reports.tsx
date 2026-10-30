import { ArrowUpRight, Download, FileText, Printer } from "lucide-react";
import { Link } from "react-router-dom";
import {
  Button,
  Card,
  Empty,
  ErrorBox,
  fmtDate,
  Loading,
  PageHeader,
  Pill,
  Stat,
  strategyLabel,
  VerdictBadge,
  vulnLabel,
} from "../components/ui";
import { useAction, useApi } from "../hooks/useApi";
import { api } from "../services/api";

export function Reports() {
  const reports = useApi(() => api.listReports());
  const download = useAction();
  return (
    <>
      <PageHeader
        title="Evidence & reports"
        subtitle="The record behind every verdict. Review executed tests, inspect patch strategies, and export investigation evidence."
        actions={
          <Button
            variant="secondary"
            onClick={() => window.print()}
            className="no-print"
          >
            <Printer size={15} />
            Print / Save as PDF
          </Button>
        }
      />
      <ErrorBox error={reports.error} onRetry={reports.reload} />
      <ErrorBox error={download.error} />
      {reports.loading && <Loading />}
      {reports.data && (
        <>
          <div className="mb-6 grid grid-cols-2 gap-4 lg:grid-cols-4">
            <Stat
              label="Evidence reports"
              value={reports.data.length}
              hint="Executed verification runs"
            />
            <Stat
              label="Verified"
              value={
                reports.data.filter((r) => r.verdict === "VERIFIED").length
              }
              accent="text-emerald-400"
              hint="All proof checks passed"
            />
            <Stat
              label="Failed"
              value={reports.data.filter((r) => r.verdict === "FAILED").length}
              accent="text-rose-400"
              hint="Proof checks failed"
            />
            <Stat
              label="Baseline replays"
              value={reports.data.filter((r) => r.kind === "baseline").length}
              hint="Original exploit investigations"
            />
          </div>
          {reports.data.length > 0 &&
            !api.reportUrl(reports.data[0].report_id, "json") && (
              <p className="mb-5 text-xs text-slate-400">
                Report downloads require the real backend. Captured demo
                evidence remains available below.
              </p>
            )}
          <div className="grid gap-5 md:grid-cols-2 xl:grid-cols-3">
            {reports.data.map((r) => (
              <Card
                key={r.report_id}
                title={
                  <span className="flex items-center gap-2">
                    <FileText size={15} className="text-brand-violet" />
                    {vulnLabel(r.scenario)}
                  </span>
                }
                actions={<ArrowUpRight size={15} className="text-slate-500" />}
              >
                <div className="flex flex-wrap items-center justify-between gap-3">
                  <Pill className="border-command-border text-slate-400">
                    {r.kind === "proof_of_fix" ? "PROOF-OF-FIX" : "BASELINE"}
                  </Pill>
                  <VerdictBadge verdict={r.verdict} />
                </div>
                <p className="mt-5 text-xs text-slate-300">
                  {r.patch_strategy
                    ? strategyLabel(r.patch_strategy)
                    : r.original_vulnerability_reproduced
                      ? "Original vulnerability reproduced"
                      : "Baseline replay evidence"}
                </p>
                <dl className="mt-4 space-y-2 text-[10px]">
                  <div className="flex justify-between gap-3">
                    <dt className="text-slate-500">Evidence ID</dt>
                    <dd className="font-mono text-slate-400">
                      {r.report_id.slice(0, 12)}
                    </dd>
                  </div>
                  <div className="flex justify-between gap-3">
                    <dt className="text-slate-500">Recorded</dt>
                    <dd className="text-slate-400">{fmtDate(r.created_at)}</dd>
                  </div>
                  <div className="flex justify-between gap-3">
                    <dt className="text-slate-500">Runner status</dt>
                    <dd className="font-mono text-slate-400">{r.status}</dd>
                  </div>
                </dl>
                <div className="mt-5 flex flex-wrap items-center gap-3 border-t border-command-border pt-4">
                  <Link
                    className="panel-link mr-auto"
                    to={`/verification/${r.report_id}`}
                  >
                    Inspect evidence <ArrowUpRight size={13} />
                  </Link>
                  {(["html", "json"] as const).map((format) => (
                    <Button
                      key={format}
                      variant="ghost"
                      className="px-1 py-1 text-[10px]"
                      disabled={
                        download.busy || !api.reportUrl(r.report_id, format)
                      }
                      title={
                        api.reportUrl(r.report_id, format)
                          ? `Download ${format.toUpperCase()} evidence`
                          : "Downloads require the real backend"
                      }
                      aria-label={`Download ${format.toUpperCase()} report ${r.report_id}`}
                      onClick={() =>
                        void download.run(() =>
                          api.downloadReport(r.report_id, format),
                        )
                      }
                    >
                      <Download size={12} />
                      {format.toUpperCase()}
                    </Button>
                  ))}
                </div>
              </Card>
            ))}
          </div>
          {reports.data.length === 0 && (
            <Card>
              <Empty>
                No verification evidence yet.{" "}
                <Link className="text-sky-400" to="/replay">
                  Open the Attack Replay Lab
                </Link>{" "}
                to record an investigation.
              </Empty>
            </Card>
          )}
        </>
      )}
    </>
  );
}
