import { ArrowRight, FileText } from "lucide-react";
import { Link } from "react-router-dom";
import { Card, Empty, ErrorBox, fmtDate, Loading, PageHeader, Pill, strategyLabel, VerdictBadge, vulnLabel } from "../components/ui";
import { useApi } from "../hooks/useApi";
import { api } from "../services/api";

export function Reports() {
  const reports = useApi(() => api.listReports());
  return (
    <>
      <PageHeader
        title="Verification reports"
        subtitle="One report per executed verification run. These are verification reports, not security certifications."
      />
      <Card
        title={
          <span className="inline-flex items-center gap-2">
            <FileText className="h-4 w-4 text-sky-400" />
            All reports
          </span>
        }
      >
        <ErrorBox error={reports.error} onRetry={reports.reload} />
        {reports.loading && <Loading />}
        {reports.data?.length === 0 && (
          <Empty>
            No verification runs yet. Use the{" "}
            <Link to="/replay" className="text-sky-400 hover:underline">
              Attack Replay Lab
            </Link>{" "}
            or a patch's "Run Proof-of-Fix".
          </Empty>
        )}
        {!!reports.data?.length && (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[700px] text-left text-sm">
              <thead>
                <tr className="text-[11px] font-semibold uppercase tracking-widest text-slate-500">
                  <th className="pb-3">When</th>
                  <th className="pb-3">Type</th>
                  <th className="pb-3">Vulnerability</th>
                  <th className="pb-3">Patch</th>
                  <th className="pb-3">Result</th>
                  <th className="pb-3 text-right">Links</th>
                </tr>
              </thead>
              <tbody>
                {reports.data.map((r) => {
                  const html = api.reportUrl(r.report_id, "html");
                  return (
                    <tr key={r.report_id} className="border-t border-slate-800/60 group">
                      <td className="py-3 text-xs tabular-nums text-slate-400">{fmtDate(r.created_at)}</td>
                      <td className="py-3">
                        <Pill className={r.kind === "proof_of_fix"
                          ? "bg-sky-500/10 text-sky-300 ring-sky-500/30"
                          : "bg-slate-700/30 text-slate-300 ring-slate-600"
                        }>
                          {r.kind === "proof_of_fix" ? "Proof-of-Fix" : "Baseline replay"}
                        </Pill>
                      </td>
                      <td className="py-3 font-medium text-slate-200">{vulnLabel(r.scenario)}</td>
                      <td className="py-3 text-slate-400 text-xs">
                        {r.patch_strategy ? strategyLabel(r.patch_strategy) : <span className="text-slate-600">—</span>}
                      </td>
                      <td className="py-3">
                        {r.kind === "proof_of_fix" ? (
                          <VerdictBadge verdict={r.verdict} />
                        ) : (
                          <Pill
                            className={
                              r.original_vulnerability_reproduced
                                ? "bg-rose-500/15 text-rose-300 ring-rose-500/40"
                                : "bg-slate-700/30 text-slate-300 ring-slate-600"
                            }
                          >
                            {r.original_vulnerability_reproduced ? "EXPLOIT REPRODUCED" : "NOT REPRODUCED"}
                          </Pill>
                        )}
                      </td>
                      <td className="py-3 text-right">
                        <div className="inline-flex items-center gap-3">
                          <Link
                            className="inline-flex items-center gap-1 text-xs font-medium text-sky-400 hover:underline"
                            to={`/verification/${r.report_id}`}
                          >
                            View <ArrowRight className="h-3 w-3" />
                          </Link>
                          {html && (
                            <a
                              className="text-xs font-medium text-slate-400 hover:text-slate-200 hover:underline"
                              href={html}
                              target="_blank"
                              rel="noreferrer"
                            >
                              HTML ↗
                            </a>
                          )}
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </>
  );
}
