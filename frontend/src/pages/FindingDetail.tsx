import { Bot, Wrench } from "lucide-react";
import { useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { CodeBlock } from "../components/CodeBlock";
import { Button, Card, ErrorBox, Loading, PageHeader, PatchStatusBadge, SeverityBadge, strategyLabel, vulnLabel } from "../components/ui";
import { useAction, useApi } from "../hooks/useApi";
import { api } from "../services/api";
import type { AIExplanation } from "../types/api";

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <h3 className="mb-1 text-xs font-semibold uppercase tracking-wide text-slate-500">{label}</h3>
      <div className="text-sm leading-relaxed text-slate-300">{children}</div>
    </div>
  );
}

/** Plain-text rendering of model output: "#" lines become headings, "**" markers are dropped. Never HTML. */
function AIText({ text }: { text: string }) {
  return (
    <div className="space-y-1 break-words text-sm leading-relaxed text-slate-300">
      {text.split("\n").map((line, i) => {
        const clean = line.replace(/\*\*/g, "");
        const heading = clean.match(/^#{1,6}\s+(.*)/);
        if (heading) return <h4 key={i} className="pt-2 font-semibold text-slate-100">{heading[1]}</h4>;
        return clean.trim() ? <p key={i} className="whitespace-pre-wrap">{clean}</p> : null;
      })}
    </div>
  );
}

export function FindingDetail() {
  const { findingId = "" } = useParams();
  const finding = useApi(() => api.getFinding(findingId), [findingId]);
  const generate = useAction();
  const explain = useAction();
  const [ai, setAi] = useState<AIExplanation | null>(null);
  const navigate = useNavigate();
  const f = finding.data;

  if (finding.loading && !f) return <Loading />;
  if (!f) return <ErrorBox error={finding.error} onRetry={finding.reload} />;

  const onGenerate = async (strategy: string) => {
    const patch = await generate.run(() => api.generatePatch(f.id, strategy));
    if (patch) navigate(`/patches/${patch.id}`);
  };
  const ev = f.evidence as Record<string, unknown>;
  const inputs = (ev.interpolated_inputs as { name: string; source: string; line: number | null; user_controlled: boolean }[]) ?? [];

  return (
    <>
      <PageHeader
        title={vulnLabel(f.vuln_type)}
        subtitle={<><Link className="text-sky-400 hover:underline" to={`/scans/${f.scan_id}`}>← Scan results</Link> · {f.cwe} · {f.title}</>}
        actions={<SeverityBadge severity={f.severity} />}
      />
      <div className="grid gap-4 xl:grid-cols-[minmax(0,1.4fr)_minmax(0,1fr)]">
        <div className="space-y-4">
          <Card title={<span className="font-mono">{f.file_path}:{f.line_start}-{f.line_end}</span>}>
            <CodeBlock code={f.code_snippet} startLine={f.snippet_start_line} highlightStart={f.line_start} highlightEnd={f.line_end} />
            {inputs.length > 0 && (
              <div className="mt-4">
                <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-slate-500">Data flow into the query</h3>
                <ul className="space-y-1 text-sm">
                  {inputs.map((i) => (
                    <li key={i.name} className="font-mono text-slate-300">
                      <span className={i.user_controlled ? "text-rose-300" : "text-slate-400"}>{i.name}</span> ← {i.source}
                      {i.line && <span className="text-slate-500"> (line {i.line})</span>}
                      {i.user_controlled && <span className="ml-2 font-sans text-xs text-rose-300">user-controlled</span>}
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </Card>
          <Card title="Explanation">
            <div className="space-y-4">
              <Field label="What is wrong">{f.explanation}</Field>
              <Field label="Impact">{f.impact}</Field>
              <Field label={`Severity rationale (${f.severity}, confidence ${f.confidence})`}>{f.severity_rationale}</Field>
              <Field label="Remediation">{f.remediation}</Field>
              <Field label="How it was detected">{f.detection_method}</Field>
            </div>
          </Card>
        </div>

        <div className="space-y-4">
          <Card title={<span className="inline-flex items-center gap-2"><Wrench className="h-4 w-4 text-sky-400" />Generate a patch</span>}>
            <p className="mb-3 text-sm text-slate-400">Generating a patch changes nothing on disk. You review the diff and approve it first.</p>
            <div className="flex flex-col gap-2">
              {f.available_strategies.map((s) => (
                <Button key={s} variant={s === "deny_all_demo" ? "secondary" : "primary"} busy={generate.busy} onClick={() => onGenerate(s)}>
                  {strategyLabel(s)}
                </Button>
              ))}
            </div>
            {f.available_strategies.includes("deny_all_demo") && (
              <p className="mt-2 text-xs text-amber-300/80">The deny-all option is a deliberately bad patch, to demonstrate that PatchProof rejects fixes that break legitimate users.</p>
            )}
            <ErrorBox error={generate.error} />
            {f.patches.length > 0 && (
              <div className="mt-4 border-t border-slate-800 pt-3">
                <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-slate-500">Patches for this finding</h3>
                <ul className="space-y-2 text-sm">
                  {f.patches.map((p) => (
                    <li key={p.id} className="flex items-center justify-between gap-2">
                      <Link className="text-sky-400 hover:underline" to={`/patches/${p.id}`}>{strategyLabel(p.strategy)}</Link>
                      <PatchStatusBadge status={p.status} />
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </Card>

          <Card title={<span className="inline-flex items-center gap-2"><Bot className="h-4 w-4 text-sky-400" />AI explanation (optional)</span>}>
            {!ai?.available && <Button variant="secondary" busy={explain.busy} onClick={async () => setAi((await explain.run(() => api.explainFinding(f.id))) ?? null)}>{ai ? "Try again" : "Ask local AI (Ollama)"}</Button>}
            <ErrorBox error={explain.error} />
            {ai && !ai.available && <p className="mt-3 text-sm text-slate-400">{ai.message}</p>}
            {ai?.text && (
              <>
                <p className="mb-2 rounded bg-amber-500/10 px-2 py-1 text-xs text-amber-300">{ai.advisory}</p>
                <AIText text={ai.text} />
                <p className="mt-2 text-xs text-slate-500">Model: {ai.model}</p>
              </>
            )}
          </Card>
        </div>
      </div>
    </>
  );
}
