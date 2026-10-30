import { FileCode2 } from "lucide-react";
import { Link, useParams } from "react-router-dom";
import { Card, Empty, ErrorBox, fmtDate, Loading, PageHeader, SeverityBadge, vulnLabel } from "../components/ui";
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
      <ErrorBox error={scan.error ?? findings.error} />
      {s?.warnings.length ? (
        <Card title="Scanner warnings" className="mb-4">
          <ul className="list-disc pl-5 text-sm text-amber-300">{s.warnings.map((w) => <li key={w}>{w}</li>)}</ul>
        </Card>
      ) : null}
      {s?.error && <ErrorBox error={new Error(s.error)} />}
      {findings.loading && <Loading />}
      {findings.data?.length === 0 && (
        <Card><Empty>No supported SQL injection or IDOR patterns were found. This does not prove the code is secure — see the README's analysis scope.</Empty></Card>
      )}
      <div className="space-y-3">
        {findings.data?.map((f) => (
          <Link key={f.id} to={`/findings/${f.id}`}
            className="block rounded-xl border border-slate-800 bg-slate-900/60 p-5 transition hover:border-sky-500/50">
            <div className="flex flex-wrap items-center gap-3">
              <SeverityBadge severity={f.severity} />
              <span className="font-medium text-white">{vulnLabel(f.vuln_type)}</span>
              <span className="text-xs text-slate-500">{f.cwe} · confidence {f.confidence}</span>
            </div>
            <div className="mt-2 flex items-center gap-2 font-mono text-sm text-sky-300">
              <FileCode2 className="h-4 w-4" /> {f.file_path}:{f.line_start}{f.line_end !== f.line_start && `-${f.line_end}`}
            </div>
            <p className="mt-2 line-clamp-2 text-sm text-slate-400">{f.explanation}</p>
          </Link>
        ))}
      </div>
    </>
  );
}
