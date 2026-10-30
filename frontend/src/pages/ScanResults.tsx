import { AlertTriangle, ArrowLeft, ArrowRight, FileCode2 } from "lucide-react";
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
        subtitle={
          s && (
            <span className="inline-flex items-center gap-2 flex-wrap">
              <span>Scanned {s.files_scanned} Python file(s)</span>
              <span className="text-slate-600">·</span>
              <span className="text-xs tabular-nums">{fmtDate(s.started_at)}</span>
              <span className="text-slate-600">·</span>
              <Link className="inline-flex items-center gap-1 text-sky-400 hover:underline" to={`/projects/${s.project_id}`}>
                <ArrowLeft className="h-3.5 w-3.5" /> Back to project
              </Link>
            </span>
          )
        }
      />
      <ErrorBox error={scan.error ?? findings.error} />

      {s?.warnings.length ? (
        <Card className="mb-5">
          <div className="flex items-start gap-3 text-amber-300">
            <AlertTriangle className="h-5 w-5 shrink-0 mt-0.5" />
            <div>
              <p className="text-sm font-semibold mb-2">Scanner warnings</p>
              <ul className="space-y-1">
                {s.warnings.map((w) => (
                  <li key={w} className="text-sm text-amber-200/80">{w}</li>
                ))}
              </ul>
            </div>
          </div>
        </Card>
      ) : null}

      {s?.error && <ErrorBox error={new Error(s.error)} />}
      {findings.loading && <Loading />}
      {findings.data?.length === 0 && (
        <Card>
          <Empty>
            No supported SQL injection or IDOR patterns found. This does not prove the code is secure — see the README's analysis scope.
          </Empty>
        </Card>
      )}

      <div className="space-y-3">
        {findings.data?.map((f) => (
          <Link
            key={f.id}
            to={`/findings/${f.id}`}
            className="group flex flex-col gap-3 rounded-2xl border border-slate-800/60 bg-slate-900/50 p-5 shadow-sm transition-all hover:border-sky-500/40 hover:shadow-lg hover:shadow-sky-500/5"
          >
            <div className="flex flex-wrap items-center gap-3">
              <SeverityBadge severity={f.severity} />
              <span className="font-semibold text-white">{vulnLabel(f.vuln_type)}</span>
              <span className="ml-auto text-[11px] text-slate-500">
                {f.cwe} · confidence {f.confidence}
              </span>
            </div>
            <div className="flex items-center gap-2 font-mono text-sm text-sky-300/80">
              <FileCode2 className="h-4 w-4 shrink-0" />
              {f.file_path}:{f.line_start}{f.line_end !== f.line_start && `-${f.line_end}`}
            </div>
            <p className="line-clamp-2 text-sm leading-relaxed text-slate-400">{f.explanation}</p>
            <div className="flex items-center justify-end">
              <span className="inline-flex items-center gap-1.5 text-xs font-medium text-sky-400 opacity-0 transition group-hover:opacity-100">
                View details <ArrowRight className="h-3.5 w-3.5" />
              </span>
            </div>
          </Link>
        ))}
      </div>
    </>
  );
}
