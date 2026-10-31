import { X } from "lucide-react";
import { Link, useSearchParams } from "react-router-dom";
import { FindingsTable } from "../components/FindingsTable";
import { Card, ErrorBox, Loading, PageHeader, Pill } from "../components/ui";
import { useT } from "../i18n";
import { useApi } from "../hooks/useApi";
import { api } from "../services/api";
import type { Finding, Severity } from "../types/api";

const SEVERITIES: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];

/**
 * The backend has no "all findings" endpoint, so this combines the findings of each
 * project's LATEST scan (GET /projects, then GET /scans/{id}/findings per project).
 * Older scans are not shown: a re-scan after patching supersedes them.
 * A ?severity=CRITICAL,HIGH query param (used by the dashboard metric cards) filters the list.
 */
export function Findings() {
  const t = useT();
  const [params, setParams] = useSearchParams();
  const sevParam = (params.get("severity") ?? "")
    .split(",").map((s) => s.trim().toUpperCase()).filter((s): s is Severity => (SEVERITIES as string[]).includes(s));

  const data = useApi(async () => {
    const projects = await api.listProjects();
    const withScans = projects.filter((p) => p.latest_scan);
    const lists = await Promise.all(withScans.map((p) => api.getScanFindings(p.latest_scan!.id)));
    const projectName = new Map(withScans.map((p) => [p.id, p.name]));
    return { findings: lists.flat() as Finding[], projectName, scanned: withScans.length, total: projects.length };
  });
  const d = data.data;
  const shown = d && sevParam.length ? d.findings.filter((f) => sevParam.includes(f.severity)) : d?.findings;

  return (
    <>
      <PageHeader title={t("findings.title")} subtitle={t("findings.subtitle")} />
      {sevParam.length > 0 && (
        <div className="mb-4 flex items-center gap-3">
          <Pill className="bg-brand/15 text-brand ring-brand/40">{t("findings.filterSeverity", { sev: sevParam.join(" / ") })}</Pill>
          <button onClick={() => setParams({})} className="inline-flex items-center gap-1 text-sm text-slate-400 hover:text-brand">
            <X className="h-3.5 w-3.5" /> {t("findings.clearFilter")}
          </button>
        </div>
      )}
      <ErrorBox error={data.error} onRetry={data.reload} />
      {data.loading && !d && <Loading />}
      {d && (
        <Card title={`${shown!.length} ${t("dash.findingsCount")} · ${d.scanned}`}>
          <FindingsTable
            findings={shown!}
            context={(f) => d.projectName.get(f.project_id)}
            emptyText={d.total === 0
              ? <>No projects yet. <Link className="text-sky-400 hover:underline" to="/projects">Create one</Link> and run a scan.</>
              : d.scanned === 0
                ? <>No project has been scanned yet. Use the <Link className="text-sky-400 hover:underline" to="/scanner">Scanner</Link>.</>
                : sevParam.length
                  ? "No findings match this severity filter."
                  : "The latest scans report no supported SQL injection or IDOR patterns."}
          />
        </Card>
      )}
    </>
  );
}
