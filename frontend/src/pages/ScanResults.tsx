import { Link, useParams } from "react-router-dom";
import { FindingsTable } from "../components/FindingsTable";
import { Card, ErrorBox, fmtDate, Loading, PageHeader } from "../components/ui";
import { useApi } from "../hooks/useApi";
import { api } from "../services/api";

export function ScanResults() {
  const { scanId = "" } = useParams();
  const scan = useApi(() => api.getScan(scanId), [scanId]);
  const findings = useApi(() => api.getScanFindings(scanId), [scanId]);
  const s = scan.data;

  return (
    <>
      <PageHeader
        title="Scan results"
        subtitle={s && <>Scanned {s.files_scanned} Python file(s) · {fmtDate(s.started_at)} · <Link className="text-sky-400 hover:underline" to={`/projects/${s.project_id}`}>Back to project</Link></>}
      />
      <ErrorBox error={scan.error ?? findings.error} onRetry={() => { void scan.reload(); void findings.reload(); }} />
      {s?.warnings.length ? (
        <Card title="Scanner warnings" className="mb-4">
          <ul className="list-disc pl-5 text-sm text-amber-300">{s.warnings.map((w) => <li key={w}>{w}</li>)}</ul>
        </Card>
      ) : null}
      {s?.error && <ErrorBox error={new Error(s.error)} />}
      {findings.loading && <Loading />}
      {findings.data && (
        <FindingsTable
          findings={findings.data}
          emptyText="No supported SQL injection or IDOR patterns were found. This does not prove the code is secure — see the README's analysis scope."
        />
      )}
    </>
  );
}
