import { Download, FileText } from "lucide-react";
import { Link, useParams } from "react-router-dom";
import { AttackTimeline } from "../components/AttackTimeline";
import { DiffView } from "../components/CodeBlock";
import { GauntletSummaryCard } from "../components/GauntletParts";
import { ExploitComparison, RunPhases, VerdictPanel } from "../components/RunView";
import { Button, Card, ErrorBox, fmtDate, Loading, PageHeader, PatchStatusBadge, SeverityBadge, strategyLabel, vulnLabel } from "../components/ui";
import { useAction, useApi } from "../hooks/useApi";
import { api, USE_MOCKS } from "../services/api";

export function VerificationResult() {
  const { runId = "" } = useParams();
  const run = useApi(() => api.getRun(runId), [runId]);
  const report = useApi(() => (USE_MOCKS ? Promise.resolve(null) : api.getReport(runId)), [runId]);
  const download = useAction();
  const r = run.data;
  const rep = report.data;
  // Full patch record gives real approval/apply/rollback timestamps; the report's patch is the fallback.
  const patchId = r?.patch_id ?? null;
  const patch = useApi(() => (patchId ? api.getPatch(patchId) : Promise.resolve(null)), [patchId]);

  if (run.loading && !r) return <Loading />;
  if (!r) return <ErrorBox error={run.error} onRetry={run.reload} />;
  const html = api.reportUrl(r.id, "html");

  return (
    <>
      <PageHeader
        title={r.kind === "proof_of_fix" ? "Proof-of-Fix result" : "Baseline exploit replay"}
        subtitle={<>{vulnLabel(r.scenario)} · run {fmtDate(r.started_at)} · {r.duration_ms ?? "?"} ms{r.patch_id && <> · <Link className="text-sky-400 hover:underline" to={`/patches/${r.patch_id}`}>View patch</Link></>}</>}
        actions={<>
          {r.patch_status && <PatchStatusBadge status={r.patch_status} />}
          {html && <>
          <a className="inline-flex items-center gap-2 rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-sm hover:bg-slate-700" href={html} target="_blank" rel="noreferrer"><FileText className="h-4 w-4" />Open HTML report</a>
          <Button variant="secondary" busy={download.busy} onClick={() => download.run(() => api.downloadReport(r.id, "html"))}><Download className="h-4 w-4" />HTML</Button>
          <Button variant="secondary" busy={download.busy} onClick={() => download.run(() => api.downloadReport(r.id, "json"))}><Download className="h-4 w-4" />JSON</Button>
          </>}
        </>}
      />
      <ErrorBox error={download.error} />
      <div className="space-y-4">
        <AttackTimeline
          scenario={r.scenario}
          baseline={r.kind === "baseline" ? r : null}
          proof={r.kind === "proof_of_fix" ? r : null}
          patch={patch.data ?? rep?.patch ?? null}
          finding={rep?.finding ? { ...rep.finding, recordedAt: rep.scan?.started_at ?? null } : null}
        />
        <VerdictPanel run={r} />
        <GauntletSummaryCard run={r} />

        {rep?.finding && (
          <div className="grid gap-4 lg:grid-cols-2">
            <Card title="What was verified">
              <div className="mb-2 flex flex-wrap items-center gap-2">
                <SeverityBadge severity={rep.finding.severity} />
                <Link className="text-slate-100 hover:text-sky-300" to={`/findings/${rep.finding.id}`}>{rep.finding.title}</Link>
              </div>
              <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-sm">
                <dt className="text-slate-500">Location</dt><dd className="break-all font-mono text-sky-300">{rep.finding.file_path}:{rep.finding.line_start}-{rep.finding.line_end}</dd>
                <dt className="text-slate-500">CWE</dt><dd>{rep.finding.cwe} · confidence {rep.finding.confidence}</dd>
                <dt className="text-slate-500">Project</dt><dd>{rep.project.name}</dd>
                {rep.patch && <>
                  <dt className="text-slate-500">Patch</dt><dd>{strategyLabel(rep.patch.strategy)}</dd>
                  <dt className="text-slate-500">Approved</dt><dd>{rep.patch.approved_by ?? "—"} · {fmtDate(rep.patch.approved_at)}</dd>
                </>}
                <dt className="text-slate-500">Completed</dt><dd>{fmtDate(rep.generated_at)}</dd>
              </dl>
            </Card>
            {rep.patch && <Card title="Patch that was tested"><DiffView diff={rep.patch.diff} /></Card>}
          </div>
        )}
        {report.error && <ErrorBox error={report.error} onRetry={report.reload} />}

        {r.kind === "proof_of_fix" && <ExploitComparison run={r} />}
        <RunPhases run={r} />

        {rep && (
          <Card title="Known limitations (from the report)">
            <ul className="list-disc space-y-1 pl-5 text-sm text-slate-400">{rep.known_limitations.map((l) => <li key={l}>{l}</li>)}</ul>
          </Card>
        )}
      </div>
    </>
  );
}
