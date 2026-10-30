import { Link } from "react-router-dom";
import { FindingsTable } from "../components/FindingsTable";
import { Card, ErrorBox, Loading, PageHeader } from "../components/ui";
import { useApi } from "../hooks/useApi";
import { api } from "../services/api";
import type { Finding } from "../types/api";

/**
 * The backend has no "all findings" endpoint, so this combines the findings of each
 * project's LATEST scan (GET /projects, then GET /scans/{id}/findings per project).
 * Older scans are not shown: a re-scan after patching supersedes them.
 */
export function Findings() {
  const data = useApi(async () => {
    const projects = await api.listProjects();
    const withScans = projects.filter((p) => p.latest_scan);
    const lists = await Promise.all(withScans.map((p) => api.getScanFindings(p.latest_scan!.id)));
    const projectName = new Map(withScans.map((p) => [p.id, p.name]));
    return { findings: lists.flat() as Finding[], projectName, scanned: withScans.length, total: projects.length };
  });
  const d = data.data;

  return (
    <>
      <PageHeader
        title="Findings"
        subtitle="Open findings from each project's most recent scan. Re-scan a project after patching to update this list."
      />
      <ErrorBox error={data.error} onRetry={data.reload} />
      {data.loading && !d && <Loading />}
      {d && (
        <Card title={`${d.findings.length} finding(s) across ${d.scanned} scanned project(s)`}>
          <FindingsTable
            findings={d.findings}
            context={(f) => d.projectName.get(f.project_id)}
            emptyText={d.total === 0
              ? <>No projects yet. <Link className="text-sky-400 hover:underline" to="/projects">Create one</Link> and run a scan.</>
              : d.scanned === 0
                ? <>No project has been scanned yet. Use the <Link className="text-sky-400 hover:underline" to="/scanner">Scanner</Link>.</>
                : "The latest scans report no supported SQL injection or IDOR patterns."}
          />
        </Card>
      )}
    </>
  );
}
