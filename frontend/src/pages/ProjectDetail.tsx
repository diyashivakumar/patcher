import { FlaskConical, ScanSearch } from "lucide-react";
import { Link, useNavigate, useParams } from "react-router-dom";
import {
  Button,
  Card,
  Empty,
  ErrorBox,
  fmtDate,
  Loading,
  PageHeader,
  SeverityBadge,
  Stat,
} from "../components/ui";
import { useAction, useApi } from "../hooks/useApi";
import { api } from "../services/api";

export function ProjectDetail() {
  const { projectId = "" } = useParams();
  const project = useApi(() => api.getProject(projectId), [projectId]);
  const scan = useAction();
  const navigate = useNavigate();
  const p = project.data;

  const onScan = async () => {
    const result = await scan.run(() => api.runScan(projectId));
    if (result) navigate(`/scans/${result.id}`);
  };

  if (project.loading && !p) return <Loading />;
  if (!p) return <ErrorBox error={project.error} onRetry={project.reload} />;

  return (
    <>
      <PageHeader
        title={p.name}
        subtitle={
          <>
            {p.description ??
              (p.source_type === "fixture"
                ? "Bundled practice fixture"
                : "Uploaded project")}{" "}
            · {p.file_count} files · {(p.total_bytes / 1024).toFixed(1)} KB
          </>
        }
        actions={
          <>
            {p.verification_supported && (
              <Link
                to={`/replay?project=${p.id}`}
                className="inline-flex items-center gap-2 rounded-lg border border-slate-700 bg-slate-800 px-3.5 py-2 text-sm hover:bg-slate-700"
              >
                <FlaskConical className="h-4 w-4" /> Attack Replay Lab
              </Link>
            )}
            <Button onClick={onScan} busy={scan.busy}>
              <ScanSearch className="h-4 w-4" />
              Run scan
            </Button>
          </>
        }
      />
      <ErrorBox error={scan.error} />
      <div className="mb-6 grid grid-cols-2 gap-4 lg:grid-cols-4">
        <Stat
          label="Source files"
          value={p.file_count}
          hint={`${(p.total_bytes / 1024).toFixed(1)} KB stored`}
        />
        <Stat
          label="Scan history"
          value={p.scan_count}
          hint="Recorded analysis runs"
        />
        <Stat
          label="Latest findings"
          value={p.latest_scan?.findings_count ?? "—"}
          hint={p.latest_scan ? p.latest_scan.status : "No scan recorded"}
        />
        <Stat
          label="Verification"
          value={p.verification_supported ? "Supported" : "Scan only"}
          accent="text-sky-400"
          hint={
            p.verification_scenarios.join(" · ").toUpperCase() ||
            "Uploaded code is never executed"
          }
        />
      </div>
      {!p.verification_supported && (
        <div className="mb-4 rounded-lg border border-slate-700 bg-slate-900 p-3 text-sm text-slate-400">
          This is an uploaded project. PatchProof can scan it and propose
          patches, but will not execute uploaded code, so Proof-of-Fix
          verification is unavailable.
        </div>
      )}
      {p.upload_skipped.length > 0 && (
        <Card
          title={`${p.upload_skipped.length} files were not stored from the upload`}
          className="mb-4"
        >
          <ul className="space-y-1 text-sm text-slate-400">
            {p.upload_skipped.map((s) => (
              <li key={s.path}>
                <code className="text-slate-300">{s.path}</code> — {s.reason}
              </li>
            ))}
          </ul>
        </Card>
      )}
      <Card title="Scan history">
        {p.scans.length === 0 ? (
          <Empty>
            No scans yet. Click <b>Run scan</b> to analyse the source code.
          </Empty>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[620px] text-left text-sm">
              <thead className="text-xs uppercase tracking-wide text-slate-500">
                <tr>
                  <th className="pb-2">Started</th>
                  <th className="pb-2">Status</th>
                  <th className="pb-2">Files</th>
                  <th className="pb-2">Findings</th>
                  <th className="pb-2">Severity</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {p.scans.map((s) => (
                  <tr key={s.id} className="border-t border-slate-800">
                    <td className="py-2.5 text-slate-400">
                      {fmtDate(s.started_at)}
                    </td>
                    <td className="py-2.5">{s.status}</td>
                    <td className="py-2.5 tabular-nums">{s.files_scanned}</td>
                    <td className="py-2.5 tabular-nums">{s.findings_count}</td>
                    <td className="space-x-1 py-2.5">
                      {(["CRITICAL", "HIGH", "MEDIUM", "LOW"] as const)
                        .filter((k) => s.severity_counts[k])
                        .map((k) => (
                          <span key={k}>
                            <SeverityBadge severity={k} />{" "}
                            <span className="mr-2 text-xs text-slate-400">
                              ×{s.severity_counts[k]}
                            </span>
                          </span>
                        ))}
                    </td>
                    <td className="py-2.5 text-right">
                      <Link
                        className="text-sky-400 hover:underline"
                        to={`/scans/${s.id}`}
                      >
                        Findings
                      </Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </>
  );
}
