import { Link, useParams } from "react-router-dom";
import { FindingsTable } from "../components/FindingsTable";
import { SeverityChart } from "../components/SecurityVisuals";
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
        subtitle={
          s && (
            <>
              Scanned {s.files_scanned} Python file(s) · {fmtDate(s.started_at)}{" "}
              ·{" "}
              <Link
                className="text-sky-400 hover:underline"
                to={`/projects/${s.project_id}`}
              >
                Back to project
              </Link>
            </>
          )
        }
      />
      <ErrorBox
        error={scan.error ?? findings.error}
        onRetry={() => {
          void scan.reload();
          void findings.reload();
        }}
      />
      {s && (
        <div className="mb-6 grid gap-5 md:grid-cols-2">
          <Card
            title="Scan telemetry"
            subtitle="Backend-reported analysis results"
          >
            <div className="scan-telemetry">
              <div>
                <span>RUN STATUS</span>
                <strong
                  className={
                    s.status === "FAILED" ? "text-rose-400" : "text-sky-400"
                  }
                >
                  {s.status}
                </strong>
              </div>
              <div>
                <span>FILES ANALYSED</span>
                <strong>{s.files_scanned}</strong>
              </div>
              <div>
                <span>FINDINGS</span>
                <strong>{s.findings_count}</strong>
              </div>
            </div>
          </Card>
          <Card title="Severity profile">
            <SeverityChart counts={s.severity_counts} />
          </Card>
        </div>
      )}
      {s?.warnings.length ? (
        <Card title="Scanner warnings" className="mb-4">
          <ul className="list-disc pl-5 text-sm text-amber-300">
            {s.warnings.map((w) => (
              <li key={w}>{w}</li>
            ))}
          </ul>
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
