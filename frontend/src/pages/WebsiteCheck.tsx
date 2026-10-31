import { AlertTriangle, CheckCircle2, Globe, Info, ShieldAlert, XCircle } from "lucide-react";
import { useState, type FormEvent } from "react";
import { Button, Card, Empty, ErrorBox, PageHeader, Pill } from "../components/ui";
import { useAction } from "../hooks/useApi";
import { api } from "../services/api";
import type { SiteCheck, SiteCheckItem } from "../types/api";

const input = "w-full rounded-lg border border-line bg-surface-2/60 px-3 py-2 text-sm text-slate-100 placeholder:text-slate-600 focus:border-brand focus:outline-none";

const STATUS: Record<SiteCheckItem["status"], { style: string; Icon: typeof CheckCircle2 }> = {
  PASS: { style: "text-verified", Icon: CheckCircle2 },
  WARNING: { style: "text-blocked", Icon: AlertTriangle },
  ERROR: { style: "text-breached", Icon: XCircle },
  INFO: { style: "text-slate-400", Icon: Info },
};

function CheckRow({ c }: { c: SiteCheckItem }) {
  const { style, Icon } = STATUS[c.status];
  return (
    <div className="flex items-start gap-3 border-t border-line/10 py-3 first:border-t-0">
      <Icon className={`mt-0.5 h-4 w-4 shrink-0 ${style}`} />
      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-center gap-2">
          <span className="font-medium text-slate-100">{c.name}</span>
          <span className={`text-[11px] font-semibold uppercase tracking-wide ${style}`}>{c.status}</span>
        </div>
        <p className="mt-0.5 text-sm text-slate-400">{c.explanation}</p>
        {c.evidence && <p className="mt-1 break-all font-mono text-[11px] text-slate-500">{c.evidence}</p>}
        {c.remediation && <p className="mt-1 text-xs text-brand/90">Fix: {c.remediation}</p>}
      </div>
    </div>
  );
}

export function WebsiteCheck() {
  const [url, setUrl] = useState("");
  const [authorized, setAuthorized] = useState(false);
  const [result, setResult] = useState<SiteCheck | null>(null);
  const run = useAction();

  const onSubmit = async (e: FormEvent) => {
    e.preventDefault();
    const r = await run.run(() => api.runSiteCheck(url.trim(), authorized));
    if (r) setResult(r);
  };

  return (
    <>
      <PageHeader
        title="Live Website Security Check"
        subtitle="A non-invasive review of a public website's HTTPS, security headers, cookies and configuration. Only ordinary GET/HEAD requests are made — no scanning, brute forcing or exploitation."
      />

      <div className="grid gap-4 lg:grid-cols-[1fr_1.4fr]">
        <Card title={<span className="inline-flex items-center gap-2"><Globe className="h-4 w-4 text-brand" /> Check a site</span>}>
          <form onSubmit={onSubmit} className="space-y-3">
            <input className={input} value={url} onChange={(e) => setUrl(e.target.value)}
              placeholder="example.com or https://example.com" required />
            <label className="flex items-start gap-2 text-xs text-slate-400">
              <input type="checkbox" checked={authorized} onChange={(e) => setAuthorized(e.target.checked)}
                className="mt-0.5 h-4 w-4 rounded border-line bg-surface-2 accent-[rgb(var(--brand))]" />
              <span>I confirm I own this website or am authorized to assess it.</span>
            </label>
            <ErrorBox error={run.error} />
            <Button type="submit" busy={run.busy} disabled={!url.trim() || !authorized}>
              {run.busy ? "Checking…" : "Run check"}
            </Button>
            <div className="flex items-start gap-2 rounded-lg border border-line/20 bg-surface-2/30 p-3 text-xs text-slate-500">
              <ShieldAlert className="mt-0.5 h-3.5 w-3.5 shrink-0" />
              <span>Private, loopback, link-local and cloud-metadata addresses are rejected, and redirects are re-validated, so the check can only reach public sites. Cookie <em>values</em> and auth tokens are never collected.</span>
            </div>
          </form>
        </Card>

        <Card title="Result">
          {!result && !run.busy && <Empty icon={<Globe className="h-5 w-5" />}>Run a check to see the report here.</Empty>}
          {run.busy && <Empty icon={<Globe className="h-5 w-5" />}>Contacting {url || "the site"}…</Empty>}
          {result && !run.busy && (
            <>
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div className="min-w-0">
                  <div className="truncate font-mono text-sm text-slate-200">{result.final_url ?? result.url}</div>
                  <div className="mt-0.5 text-xs text-slate-500">
                    {result.host} → {result.resolved_ips.join(", ") || "—"}
                  </div>
                </div>
                <Pill className={result.status === "COMPLETED" ? "bg-verified/15 text-verified ring-verified/40" : "bg-breached/15 text-breached ring-breached/40"}>
                  {result.posture.summary ?? result.status}
                </Pill>
              </div>
              {result.posture.counts && (
                <div className="mt-3 flex flex-wrap gap-2 text-xs">
                  {(["PASS", "WARNING", "INFO", "ERROR"] as const).map((k) =>
                    result.posture.counts![k] ? (
                      <span key={k} className={`rounded-md px-2 py-0.5 ${STATUS[k].style}`}>{result.posture.counts![k]} {k.toLowerCase()}</span>
                    ) : null)}
                </div>
              )}
              <div className="mt-4">
                {result.checks.map((c, i) => <CheckRow key={`${c.name}-${i}`} c={c} />)}
              </div>
              <p className="mt-4 border-t border-line/10 pt-3 text-xs italic text-slate-500">{result.disclaimer}</p>
            </>
          )}
        </Card>
      </div>
    </>
  );
}
