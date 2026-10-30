import { cx } from "./ui";

/** Source code with real line numbers; lines in [highlightStart, highlightEnd] are marked. */
export function CodeBlock({ code, startLine = 1, highlightStart, highlightEnd, title }: {
  code: string; startLine?: number; highlightStart?: number; highlightEnd?: number; title?: string;
}) {
  const lines = code.replace(/\r\n/g, "\n").replace(/\n$/, "").split("\n");
  return (
    <div className="overflow-hidden rounded-lg border border-slate-800 bg-slate-950">
      {title && <div className="border-b border-slate-800 px-4 py-2 font-mono text-xs text-slate-400">{title}</div>}
      <pre className="overflow-x-auto py-2 font-mono text-[13px] leading-6">
        {lines.map((line, i) => {
          const n = startLine + i;
          const hit = highlightStart !== undefined && n >= highlightStart && n <= (highlightEnd ?? highlightStart);
          return (
            <div key={n} className={cx("flex", hit && "bg-rose-500/10")}>
              <span className={cx("w-12 shrink-0 select-none pr-4 text-right", hit ? "text-rose-300" : "text-slate-600")}>{n}</span>
              <code className={cx("whitespace-pre pr-4", hit ? "text-rose-100" : "text-slate-300")}>{line || " "}</code>
            </div>
          );
        })}
      </pre>
    </div>
  );
}

/** Unified diff with +/- colouring. */
export function DiffView({ diff }: { diff: string }) {
  const lines = diff.replace(/\r\n/g, "\n").replace(/\n$/, "").split("\n");
  return (
    <pre className="overflow-x-auto rounded-lg border border-slate-800 bg-slate-950 py-2 font-mono text-[13px] leading-6">
      {lines.map((line, i) => {
        const style = line.startsWith("+++") || line.startsWith("---")
          ? "text-slate-400"
          : line.startsWith("+") ? "bg-emerald-500/10 text-emerald-300"
          : line.startsWith("-") ? "bg-rose-500/10 text-rose-300"
          : line.startsWith("@@") ? "text-sky-400" : "text-slate-400";
        return <div key={i} className={cx("whitespace-pre px-4", style)}>{line || " "}</div>;
      })}
    </pre>
  );
}
