import { FileCode2 } from "lucide-react";
import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import type { Finding, Severity, VulnType } from "../types/api";
import { cx, Empty, SeverityBadge, vulnLabel } from "./ui";

const SEVERITIES: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
const TYPES: VulnType[] = ["sqli", "idor"];

function Chip({ active, onClick, children }: { active: boolean; onClick: () => void; children: React.ReactNode }) {
  return (
    <button onClick={onClick} className={cx("rounded-full px-3 py-1 text-xs font-medium ring-1 ring-inset transition",
      active ? "bg-sky-500/15 text-sky-300 ring-sky-500/40" : "text-slate-400 ring-slate-700 hover:text-slate-200")}>
      {children}
    </button>
  );
}

/** Findings list with client-side severity / type filters. `context` adds an optional per-row label (e.g. project name). */
export function FindingsTable({ findings, context, emptyText }: {
  findings: Finding[]; context?: (f: Finding) => React.ReactNode; emptyText: React.ReactNode;
}) {
  const [severity, setSeverity] = useState<Severity | "all">("all");
  const [type, setType] = useState<VulnType | "all">("all");
  const shown = useMemo(
    () => findings.filter((f) => (severity === "all" || f.severity === severity) && (type === "all" || f.vuln_type === type)),
    [findings, severity, type],
  );
  const count = (pred: (f: Finding) => boolean) => findings.filter(pred).length;

  if (!findings.length) return <Empty>{emptyText}</Empty>;
  return (
    <>
      <div className="mb-4 flex flex-wrap items-center gap-2">
        <span className="text-xs uppercase tracking-wide text-slate-500">Severity</span>
        <Chip active={severity === "all"} onClick={() => setSeverity("all")}>All {findings.length}</Chip>
        {SEVERITIES.filter((s) => count((f) => f.severity === s)).map((s) => (
          <Chip key={s} active={severity === s} onClick={() => setSeverity(s)}>{s} {count((f) => f.severity === s)}</Chip>
        ))}
        <span className="ml-3 text-xs uppercase tracking-wide text-slate-500">Type</span>
        <Chip active={type === "all"} onClick={() => setType("all")}>All</Chip>
        {TYPES.filter((t) => count((f) => f.vuln_type === t)).map((t) => (
          <Chip key={t} active={type === t} onClick={() => setType(t)}>{t === "sqli" ? "SQL Injection" : "IDOR"}</Chip>
        ))}
      </div>
      {!shown.length && <Empty>No findings match these filters.</Empty>}
      <div className="space-y-3">
        {shown.map((f) => (
          <Link key={f.id} to={`/findings/${f.id}`}
            className="block rounded-xl border border-slate-800 bg-slate-900/60 p-5 transition hover:border-sky-500/50">
            <div className="flex flex-wrap items-center gap-3">
              <SeverityBadge severity={f.severity} />
              <span className="font-medium text-white">{vulnLabel(f.vuln_type)}</span>
              <span className="text-xs text-slate-500">{f.cwe} · confidence {f.confidence}</span>
              {context && <span className="ml-auto text-xs text-slate-400">{context(f)}</span>}
            </div>
            <div className="mt-2 flex items-center gap-2 break-all font-mono text-sm text-sky-300">
              <FileCode2 className="h-4 w-4 shrink-0" /> {f.file_path}:{f.line_start}{f.line_end !== f.line_start && `-${f.line_end}`}
            </div>
            <p className="mt-2 line-clamp-2 text-sm text-slate-400">{f.explanation}</p>
          </Link>
        ))}
      </div>
    </>
  );
}
