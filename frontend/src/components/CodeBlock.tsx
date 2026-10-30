import { cx } from "./ui";

/** Source code with real line numbers; lines in [highlightStart, highlightEnd] are marked. */
export function CodeBlock({ code, startLine = 1, highlightStart, highlightEnd, title }: {
  code: string; startLine?: number; highlightStart?: number; highlightEnd?: number; title?: string;
}) {
  const lines = code.replace(/\r\n/g, "\n").replace(/\n$/, "").split("\n");
  return (
    <div className="overflow-hidden rounded-xl border border-slate-800/60 bg-slate-950">
      {title && (
        <div className="flex items-center gap-2 border-b border-slate-800/60 px-4 py-2">
          <div className="flex gap-1.5">
            <span className="h-2.5 w-2.5 rounded-full bg-slate-700" />
            <span className="h-2.5 w-2.5 rounded-full bg-slate-700" />
            <span className="h-2.5 w-2.5 rounded-full bg-slate-700" />
          </div>
          <span className="font-mono text-xs text-slate-500">{title}</span>
        </div>
      )}
      <pre className="overflow-x-auto py-3 font-mono text-[13px] leading-6">
        {lines.map((line, i) => {
          const n = startLine + i;
          const hit =
            highlightStart !== undefined &&
            n >= highlightStart &&
            n <= (highlightEnd ?? highlightStart);
          return (
            <div
              key={n}
              className={cx(
                "flex transition-colors",
                hit
                  ? "bg-rose-500/12 border-l-2 border-rose-500"
                  : "border-l-2 border-transparent"
              )}
            >
              <span
                className={cx(
                  "w-12 shrink-0 select-none pr-4 text-right text-[11px] leading-6",
                  hit ? "text-rose-400" : "text-slate-700"
                )}
              >
                {n}
              </span>
              <code className={cx("whitespace-pre pr-4", hit ? "text-rose-100" : "text-slate-300")}>
                {line || " "}
              </code>
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
    <div className="overflow-hidden rounded-xl border border-slate-800/60 bg-slate-950">
      <div className="flex items-center gap-2 border-b border-slate-800/60 px-4 py-2">
        <div className="flex gap-1.5">
          <span className="h-2.5 w-2.5 rounded-full bg-rose-500/60" />
          <span className="h-2.5 w-2.5 rounded-full bg-amber-500/60" />
          <span className="h-2.5 w-2.5 rounded-full bg-emerald-500/60" />
        </div>
        <span className="font-mono text-xs text-slate-500">diff</span>
      </div>
      <pre className="overflow-x-auto py-3 font-mono text-[13px] leading-6">
        {lines.map((line, i) => {
          const isAdd = !line.startsWith("+++") && line.startsWith("+");
          const isDel = !line.startsWith("---") && line.startsWith("-");
          const isHdr = line.startsWith("@@");
          const isMeta = line.startsWith("+++") || line.startsWith("---");
          const style = isMeta
            ? "text-slate-500"
            : isAdd
            ? "bg-emerald-500/10 text-emerald-300 border-l-2 border-emerald-500"
            : isDel
            ? "bg-rose-500/10 text-rose-300 border-l-2 border-rose-500"
            : isHdr
            ? "text-sky-400 bg-sky-500/5"
            : "text-slate-400 border-l-2 border-transparent";
          return (
            <div key={i} className={cx("whitespace-pre px-4", style)}>
              {line || " "}
            </div>
          );
        })}
      </pre>
    </div>
  );
}
