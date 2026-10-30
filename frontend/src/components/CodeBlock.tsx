import { useState } from "react";
import { Columns2, Rows, Copy, Check, FileCode, GitCompare } from "lucide-react";
import { cx } from "./ui";

/** Source code with real line numbers; lines in [highlightStart, highlightEnd] are marked. */
export function CodeBlock({
  code,
  startLine = 1,
  highlightStart,
  highlightEnd,
  title,
}: {
  code: string;
  startLine?: number;
  highlightStart?: number;
  highlightEnd?: number;
  title?: string;
}) {
  const [copied, setCopied] = useState(false);
  const lines = code.replace(/\r\n/g, "\n").replace(/\n$/, "").split("\n");

  const handleCopy = () => {
    navigator.clipboard.writeText(code);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="overflow-hidden rounded-xl border border-slate-800/80 bg-[#0d1117] shadow-sm">
      <div className="flex items-center justify-between border-b border-slate-800/80 bg-[#161b22] px-4 py-2">
        <div className="flex items-center gap-2 text-slate-400">
          <FileCode className="h-3.5 w-3.5 text-slate-500" />
          {title && <span className="font-mono text-xs text-slate-300 font-medium">{title}</span>}
          <span className="text-[11px] text-slate-500 font-mono">({lines.length} lines)</span>
        </div>
        <button
          onClick={handleCopy}
          className="flex items-center gap-1.5 rounded px-2 py-1 text-[11px] text-slate-400 hover:bg-slate-800 hover:text-slate-200 transition font-medium"
          title="Copy code"
        >
          {copied ? <Check className="h-3 w-3 text-emerald-400" /> : <Copy className="h-3 w-3" />}
          {copied ? "Copied" : "Copy"}
        </button>
      </div>
      <pre className="overflow-x-auto py-2.5 font-mono text-[13px] leading-6">
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
                  ? "bg-rose-500/10 border-l-2 border-rose-500 text-rose-200"
                  : "border-l-2 border-transparent text-slate-300"
              )}
            >
              <span
                className={cx(
                  "w-12 shrink-0 select-none pr-4 text-right text-[11px] leading-6",
                  hit ? "text-rose-400 font-medium" : "text-slate-600"
                )}
              >
                {n}
              </span>
              <code className="whitespace-pre pr-4 flex-1">
                {line || " "}
              </code>
            </div>
          );
        })}
      </pre>
    </div>
  );
}

interface SplitDiffRow {
  leftLine?: number;
  leftText?: string;
  leftType?: "del" | "context" | "empty";
  rightLine?: number;
  rightText?: string;
  rightType?: "add" | "context" | "empty";
}

/** Compute paired rows for side-by-side diff display. */
function parseSplitDiff(diff: string): SplitDiffRow[] {
  const lines = diff.replace(/\r\n/g, "\n").replace(/\n$/, "").split("\n");
  const rows: SplitDiffRow[] = [];

  let leftLineNum = 1;
  let rightLineNum = 1;

  let dels: string[] = [];
  let adds: string[] = [];

  const flushHunk = () => {
    const maxLen = Math.max(dels.length, adds.length);
    for (let i = 0; i < maxLen; i++) {
      const delText = dels[i];
      const addText = adds[i];
      rows.push({
        leftLine: delText !== undefined ? leftLineNum++ : undefined,
        leftText: delText,
        leftType: delText !== undefined ? "del" : "empty",
        rightLine: addText !== undefined ? rightLineNum++ : undefined,
        rightText: addText,
        rightType: addText !== undefined ? "add" : "empty",
      });
    }
    dels = [];
    adds = [];
  };

  for (const line of lines) {
    if (line.startsWith("+++") || line.startsWith("---")) {
      continue;
    }
    if (line.startsWith("@@")) {
      flushHunk();
      const match = line.match(/@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@/);
      if (match) {
        leftLineNum = parseInt(match[1], 10);
        rightLineNum = parseInt(match[2], 10);
      }
      continue;
    }

    if (line.startsWith("-")) {
      dels.push(line.slice(1));
    } else if (line.startsWith("+")) {
      adds.push(line.slice(1));
    } else {
      flushHunk();
      const text = line.startsWith(" ") ? line.slice(1) : line;
      rows.push({
        leftLine: leftLineNum++,
        leftText: text,
        leftType: "context",
        rightLine: rightLineNum++,
        rightText: text,
        rightType: "context",
      });
    }
  }

  flushHunk();
  return rows;
}

/** Unified & Side-by-Side (Split) diff viewer with toggle. */
export function DiffView({ diff, defaultMode = "unified" }: { diff: string; defaultMode?: "unified" | "split" }) {
  const [mode, setMode] = useState<"unified" | "split">(defaultMode);
  const [copied, setCopied] = useState(false);
  const lines = diff.replace(/\r\n/g, "\n").replace(/\n$/, "").split("\n");
  const splitRows = mode === "split" ? parseSplitDiff(diff) : [];

  const handleCopy = () => {
    navigator.clipboard.writeText(diff);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="overflow-hidden rounded-xl border border-slate-800/80 bg-[#0d1117] shadow-sm">
      {/* Header with View Mode Switcher */}
      <div className="flex items-center justify-between border-b border-slate-800/80 bg-[#161b22] px-4 py-2">
        <div className="flex items-center gap-2">
          <GitCompare className="h-3.5 w-3.5 text-slate-500" />
          <span className="font-mono text-xs text-slate-300 font-medium">Patch Diff</span>
        </div>

        <div className="flex items-center gap-2">
          {/* Mode Switcher */}
          <div className="flex items-center rounded-lg bg-slate-900/90 p-0.5 border border-slate-800">
            <button
              type="button"
              onClick={() => setMode("unified")}
              className={cx(
                "flex items-center gap-1.5 rounded-md px-2.5 py-1 text-xs font-medium transition-all",
                mode === "unified"
                  ? "bg-slate-800 text-white shadow-sm border border-slate-700/60"
                  : "text-slate-400 hover:text-slate-200"
              )}
            >
              <Rows className="h-3 w-3" />
              Unified
            </button>
            <button
              type="button"
              onClick={() => setMode("split")}
              className={cx(
                "flex items-center gap-1.5 rounded-md px-2.5 py-1 text-xs font-medium transition-all",
                mode === "split"
                  ? "bg-slate-800 text-white shadow-sm border border-slate-700/60"
                  : "text-slate-400 hover:text-slate-200"
              )}
            >
              <Columns2 className="h-3 w-3" />
              Split
            </button>
          </div>

          <button
            onClick={handleCopy}
            className="flex items-center gap-1.5 rounded px-2 py-1 text-[11px] text-slate-400 hover:bg-slate-800 hover:text-slate-200 transition font-medium"
            title="Copy diff"
          >
            {copied ? <Check className="h-3 w-3 text-emerald-400" /> : <Copy className="h-3 w-3" />}
            {copied ? "Copied" : "Copy"}
          </button>
        </div>
      </div>

      {/* Unified View */}
      {mode === "unified" && (
        <pre className="overflow-x-auto py-2.5 font-mono text-[13px] leading-6">
          {lines.map((line, i) => {
            const isAdd = !line.startsWith("+++") && line.startsWith("+");
            const isDel = !line.startsWith("---") && line.startsWith("-");
            const isHdr = line.startsWith("@@");
            const isMeta = line.startsWith("+++") || line.startsWith("---");
            const style = isMeta
              ? "text-slate-500 font-semibold"
              : isAdd
              ? "bg-[#1b472c]/30 text-emerald-300 border-l-2 border-emerald-500"
              : isDel
              ? "bg-[#542426]/30 text-rose-300 border-l-2 border-rose-500"
              : isHdr
              ? "text-sky-400 bg-sky-950/20 font-medium"
              : "text-slate-400 border-l-2 border-transparent";
            return (
              <div key={i} className={cx("whitespace-pre px-4", style)}>
                {line || " "}
              </div>
            );
          })}
        </pre>
      )}

      {/* Split (Side-by-Side) View */}
      {mode === "split" && (
        <div className="overflow-x-auto">
          <div className="grid grid-cols-2 border-b border-slate-800/80 bg-[#161b22] font-mono text-[11px] font-semibold text-slate-400">
            <div className="px-4 py-1.5 border-r border-slate-800/80 flex items-center gap-2">
              <span className="inline-block h-2 w-2 rounded-full bg-rose-500" />
              Original (Before)
            </div>
            <div className="px-4 py-1.5 flex items-center gap-2">
              <span className="inline-block h-2 w-2 rounded-full bg-emerald-500" />
              Proposed Patch (After)
            </div>
          </div>

          <div className="py-2 font-mono text-[13px] leading-6 min-w-[700px]">
            {splitRows.map((row, idx) => (
              <div key={idx} className="grid grid-cols-2 divide-x divide-slate-800/60 hover:bg-slate-900/30">
                {/* Left side */}
                <div
                  className={cx(
                    "flex items-start overflow-hidden px-2",
                    row.leftType === "del" && "bg-[#542426]/30 text-rose-300",
                    row.leftType === "empty" && "bg-slate-950/40 text-slate-600"
                  )}
                >
                  <span className="w-9 shrink-0 select-none pr-3 text-right text-[11px] text-slate-600">
                    {row.leftLine ?? ""}
                  </span>
                  <code className="whitespace-pre overflow-x-auto flex-1 pr-2">
                    {row.leftText ?? " "}
                  </code>
                </div>

                {/* Right side */}
                <div
                  className={cx(
                    "flex items-start overflow-hidden px-2",
                    row.rightType === "add" && "bg-[#1b472c]/30 text-emerald-300",
                    row.rightType === "empty" && "bg-slate-950/40 text-slate-600"
                  )}
                >
                  <span className="w-9 shrink-0 select-none pr-3 text-right text-[11px] text-slate-600">
                    {row.rightLine ?? ""}
                  </span>
                  <code className="whitespace-pre overflow-x-auto flex-1 pr-2">
                    {row.rightText ?? " "}
                  </code>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
