import { X } from "lucide-react";
import { Link, useSearchParams } from "react-router-dom";
import { Card, Empty, ErrorBox, fmtDate, Loading, PageHeader, Pill, strategyLabel, VerdictBadge, vulnLabel } from "../components/ui";
import { useT } from "../i18n";
import { useAction, useApi } from "../hooks/useApi";
import { api } from "../services/api";

export function Reports() {
  const t = useT();
  const [params, setParams] = useSearchParams();
  const verdict = (params.get("verdict") ?? "").toUpperCase();
  const reports = useApi(() => api.listReports());
  const download = useAction();
  const rows = verdict ? reports.data?.filter((r) => r.verdict === verdict) : reports.data;
  return (
    <>
      <PageHeader title={t("reports.title")} subtitle={t("reports.subtitle")} />
      {verdict && (
        <div className="mb-4 flex items-center gap-3">
          <Pill className="bg-brand/15 text-brand ring-brand/40">{t("reports.filterVerdict", { verdict })}</Pill>
          <button onClick={() => setParams({})} className="inline-flex items-center gap-1 text-sm text-slate-400 hover:text-brand">
            <X className="h-3.5 w-3.5" /> {t("reports.clearFilter")}
          </button>
        </div>
      )}
      <Card>
        <ErrorBox error={reports.error ?? download.error} onRetry={reports.error ? reports.reload : undefined} />
        {reports.loading && <Loading />}
        {reports.data?.length === 0 && <Empty>No verification runs yet. Use the Attack Replay Lab or a patch's “Run Proof-of-Fix”.</Empty>}
        {reports.data && rows?.length === 0 && reports.data.length > 0 && <Empty>No reports match this filter.</Empty>}
        {!!rows?.length && (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[700px] text-left text-sm">
              <thead className="text-xs uppercase tracking-wide text-slate-500">
                <tr><th className="pb-2">When</th><th className="pb-2">Type</th><th className="pb-2">Vulnerability</th><th className="pb-2">Patch</th><th className="pb-2">Result</th><th /></tr>
              </thead>
              <tbody>
                {rows.map((r) => {
                  const html = api.reportUrl(r.report_id, "html");
                  return (
                    <tr key={r.report_id} className="border-t border-slate-800">
                      <td className="py-2.5 text-slate-400">{fmtDate(r.created_at)}</td>
                      <td className="py-2.5">{r.kind === "proof_of_fix" ? "Proof-of-Fix" : "Baseline replay"}</td>
                      <td className="py-2.5">{vulnLabel(r.scenario)}</td>
                      <td className="py-2.5 text-slate-400">{r.patch_strategy ? strategyLabel(r.patch_strategy) : "—"}</td>
                      <td className="py-2.5">
                        {r.kind === "proof_of_fix" ? <VerdictBadge verdict={r.verdict} /> : (
                          <Pill className={r.original_vulnerability_reproduced ? "bg-rose-500/15 text-rose-300 ring-rose-500/40" : "bg-slate-700/30 text-slate-300 ring-slate-600"}>
                            {r.original_vulnerability_reproduced ? "EXPLOIT REPRODUCED" : "NOT REPRODUCED"}
                          </Pill>
                        )}
                      </td>
                      <td className="space-x-3 py-2.5 text-right">
                        <Link className="text-sky-400 hover:underline" to={`/verification/${r.report_id}`}>View</Link>
                        {html && <a className="text-sky-400 hover:underline" href={html} target="_blank" rel="noreferrer">HTML</a>}
                        {html && (["html", "json"] as const).map((fmt) => (
                          <button key={fmt} disabled={download.busy} className="text-sky-400 hover:underline disabled:opacity-50"
                            onClick={() => download.run(() => api.downloadReport(r.report_id, fmt))}>⤓ {fmt.toUpperCase()}</button>
                        ))}
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
