import { ArrowLeft, Bot, Info, Wrench } from "lucide-react";
import { useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { CodeBlock } from "../components/CodeBlock";
import { Button, Card, ErrorBox, Loading, PageHeader, PatchStatusBadge, SeverityBadge, strategyLabel, vulnLabel } from "../components/ui";
import { useAction, useApi } from "../hooks/useApi";
import { api } from "../services/api";
import type { AIExplanation } from "../types/api";

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="space-y-1.5">
      <h3 className="flex items-center gap-1.5 text-[10px] font-bold uppercase tracking-widest text-slate-500">
        <Info className="h-3 w-3" />
        {label}
      </h3>
      <div className="rounded-xl border border-slate-800/60 bg-slate-950/40 px-4 py-3 text-sm leading-relaxed text-slate-300">
        {children}
      </div>
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
        subtitle={
          <>
            <Link
              className="inline-flex items-center gap-1 text-sky-400 hover:underline"
              to={`/scans/${f.scan_id}`}
            >
              <ArrowLeft className="h-3.5 w-3.5" /> Scan results
            </Link>
            <span className="mx-2 text-slate-600">·</span>
            <span className="font-mono text-slate-400">{f.cwe}</span>
            <span className="mx-2 text-slate-600">·</span>
            {f.title}
          </>
        }
        actions={<SeverityBadge severity={f.severity} />}
      />

      <div className="grid gap-5 xl:grid-cols-[1.4fr_1fr]">
        {/* Left column */}
        <div className="space-y-5">
          <Card
            title={
              <span className="font-mono text-xs">
                {f.file_path}:{f.line_start}–{f.line_end}
              </span>
            }
          >
            <CodeBlock
              code={f.code_snippet}
              startLine={f.snippet_start_line}
              highlightStart={f.line_start}
              highlightEnd={f.line_end}
            />
            {inputs.length > 0 && (
              <div className="mt-4 rounded-xl border border-slate-800/60 bg-slate-950/40 p-4">
                <h3 className="mb-3 text-[10px] font-bold uppercase tracking-widest text-slate-500">
                  Data flow into the query
                </h3>
                <ul className="space-y-2">
                  {inputs.map((i) => (
                    <li key={i.name} className="flex items-center gap-2 font-mono text-sm">
                      <span
                        className={`rounded px-1.5 py-0.5 text-xs ${
                          i.user_controlled
                            ? "bg-rose-500/15 text-rose-300 ring-1 ring-inset ring-rose-500/30"
                            : "bg-slate-800 text-slate-400"
                        }`}
                      >
                        {i.name}
                      </span>
                      <span className="text-slate-600">←</span>
                      <span className="text-slate-400">{i.source}</span>
                      {i.line && <span className="text-slate-600 text-xs">(line {i.line})</span>}
                      {i.user_controlled && (
                        <span className="font-sans text-[10px] font-semibold uppercase tracking-wide text-rose-400">
                          user-controlled ⚠
                        </span>
                      )}
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </Card>

          <Card title="Explanation">
            <div className="space-y-3">
              <Field label="What is wrong">{f.explanation}</Field>
              <Field label="Impact">{f.impact}</Field>
              <Field label={`Severity rationale (${f.severity} · confidence ${f.confidence})`}>{f.severity_rationale}</Field>
              <Field label="Remediation">{f.remediation}</Field>
              <Field label="How it was detected">{f.detection_method}</Field>
            </div>
          </Card>
        </div>

        {/* Right column */}
        <div className="space-y-5">
          <Card
            title={
              <span className="inline-flex items-center gap-2">
                <Wrench className="h-4 w-4 text-sky-400" /> Generate a patch
              </span>
            }
          >
            <p className="mb-4 text-sm leading-relaxed text-slate-400">
              Generating a patch changes nothing on disk. You review the diff and approve it first.
            </p>
            <div className="flex flex-col gap-2.5">
              {f.available_strategies.map((s) => (
                <Button
                  key={s}
                  variant={s === "deny_all_demo" ? "secondary" : "primary"}
                  busy={generate.busy}
                  onClick={() => onGenerate(s)}
                  className="justify-start"
                >
                  {strategyLabel(s)}
                </Button>
              ))}
            </div>
            {f.available_strategies.includes("deny_all_demo") && (
              <div className="mt-3 flex items-start gap-2 rounded-xl border border-amber-500/20 bg-amber-500/8 px-3 py-2.5">
                <span className="text-amber-400 text-xs mt-0.5">⚠</span>
                <p className="text-xs text-amber-300/90 leading-relaxed">
                  The deny-all option is a deliberately bad patch, to demonstrate that PatchProof rejects fixes that break legitimate users.
                </p>
              </div>
            )}
            <ErrorBox error={generate.error} />
            {f.patches.length > 0 && (
              <div className="mt-4 border-t border-slate-800/60 pt-4">
                <h3 className="mb-3 text-[10px] font-bold uppercase tracking-widest text-slate-500">
                  Patches for this finding
                </h3>
                <ul className="space-y-2">
                  {f.patches.map((p) => (
                    <li key={p.id} className="flex items-center justify-between gap-2 rounded-lg border border-slate-800/60 bg-slate-950/40 px-3 py-2">
                      <Link
                        className="text-sm text-sky-400 hover:underline"
                        to={`/patches/${p.id}`}
                      >
                        {strategyLabel(p.strategy)}
                      </Link>
                      <PatchStatusBadge status={p.status} />
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </Card>

          <Card
            title={
              <span className="inline-flex items-center gap-2">
                <Bot className="h-4 w-4 text-sky-400" /> AI explanation (optional)
              </span>
            }
          >
            {!ai && (
              <Button
                variant="secondary"
                busy={explain.busy}
                onClick={async () => setAi((await explain.run(() => api.explainFinding(f.id))) ?? null)}
              >
                <Bot className="h-4 w-4" /> Ask local AI (Ollama)
              </Button>
            )}
            <ErrorBox error={explain.error} />
            {ai && !ai.available && (
              <p className="text-sm text-slate-400 leading-relaxed">{ai.message}</p>
            )}
            {ai?.text && (
              <>
                <div className="mb-3 flex items-start gap-2 rounded-xl border border-amber-500/20 bg-amber-500/8 px-3 py-2">
                  <span className="text-amber-400 text-xs mt-0.5">ℹ</span>
                  <p className="text-xs text-amber-300/90">{ai.advisory}</p>
                </div>
                <div className="whitespace-pre-wrap text-sm leading-relaxed text-slate-300">{ai.text}</div>
                <p className="mt-3 text-[11px] text-slate-600">Model: {ai.model}</p>
              </>
            )}
          </Card>
        </div>
      </div>
    </>
  );
}
