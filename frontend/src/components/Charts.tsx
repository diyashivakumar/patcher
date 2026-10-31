import { useNavigate } from "react-router-dom";
import { usePrefersReducedMotion } from "./ui";

/* ---------------------------------------------------------------- Donut chart (SVG) */
export interface DonutSlice { label: string; value: number; color: string }

export function Donut({ slices, size = 150, thickness = 16, centerTop, centerSub }: {
  slices: DonutSlice[]; size?: number; thickness?: number; centerTop?: string; centerSub?: string;
}) {
  const total = slices.reduce((n, s) => n + s.value, 0);
  const r = (size - thickness) / 2;
  const c = size / 2;
  const circ = 2 * Math.PI * r;
  let offset = 0;
  return (
    <div className="flex items-center gap-4">
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} className="shrink-0 -rotate-90">
        <circle cx={c} cy={c} r={r} fill="none" stroke="rgb(var(--line) / 0.15)" strokeWidth={thickness} />
        {total > 0 && slices.map((s) => {
          const len = (s.value / total) * circ;
          const el = (
            <circle key={s.label} cx={c} cy={c} r={r} fill="none" stroke={s.color} strokeWidth={thickness}
              strokeDasharray={`${len} ${circ - len}`} strokeDashoffset={-offset} strokeLinecap="round"
              className="draw-in" style={{ ["--len" as string]: circ }} />
          );
          offset += len;
          return el;
        })}
      </svg>
      <div className="min-w-0">
        {centerTop && <div className="text-2xl font-semibold tabular-nums text-white">{centerTop}</div>}
        {centerSub && <div className="mb-2 text-xs text-slate-500">{centerSub}</div>}
        <ul className="space-y-1 text-xs">
          {slices.map((s) => (
            <li key={s.label} className="flex items-center gap-2">
              <span className="h-2 w-2 rounded-full" style={{ background: s.color }} />
              <span className="text-slate-400">{s.label}</span>
              <span className="ml-auto font-mono tabular-nums text-slate-200">{s.value}</span>
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}

/* ---------------------------------------------------------------- Attack network topology (SVG) */
export type NodeKind = "project" | "vuln" | "patch" | "verified" | "breached" | "exposed";
export interface TopoNode { id: string; label: string; sub?: string; x: number; y: number; kind: NodeKind; to?: string }
export interface TopoLink { from: string; to: string; state?: "breached" | "verified" | "normal" }

const NODE_COLOR: Record<NodeKind, string> = {
  project: "var(--brand)", vuln: "var(--breached)", patch: "var(--violet)",
  verified: "var(--verified)", breached: "var(--breached)", exposed: "var(--breached)",
};
const LINK_COLOR = { breached: "var(--breached)", verified: "var(--verified)", normal: "var(--line)" };

export function NetworkTopology({ nodes, links, height = 360 }: { nodes: TopoNode[]; links: TopoLink[]; height?: number }) {
  const navigate = useNavigate();
  const reduce = usePrefersReducedMotion();
  const W = 1000, H = 520;
  const pos = (n: TopoNode) => ({ x: (n.x / 100) * W, y: (n.y / 100) * H });
  const byId = Object.fromEntries(nodes.map((n) => [n.id, n]));

  return (
    <div className="relative w-full overflow-hidden rounded-xl" style={{ height }}>
      <svg viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="xMidYMid meet" className="h-full w-full">
        <defs>
          <pattern id="topogrid" width="40" height="40" patternUnits="userSpaceOnUse">
            <path d="M40 0H0V40" fill="none" stroke="rgb(var(--line) / 0.07)" strokeWidth="1" />
          </pattern>
          {(["breached", "verified", "normal"] as const).map((k) => (
            <marker key={k} id={`arrow-${k}`} viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
              <path d="M0 0 L10 5 L0 10 z" fill={`rgb(${LINK_COLOR[k]})`} />
            </marker>
          ))}
        </defs>
        <rect width={W} height={H} fill="url(#topogrid)" />

        {links.map((l, i) => {
          const a = byId[l.from], b = byId[l.to];
          if (!a || !b) return null;
          const p1 = pos(a), p2 = pos(b);
          const state = l.state ?? "normal";
          return (
            <line key={i} x1={p1.x} y1={p1.y} x2={p2.x} y2={p2.y}
              stroke={`rgb(${LINK_COLOR[state]} / ${state === "normal" ? 0.3 : 0.6})`} strokeWidth={state === "normal" ? 1.5 : 2}
              markerEnd={`url(#arrow-${state})`} className={!reduce && state !== "normal" ? "link-flow" : undefined} />
          );
        })}

        {nodes.map((n) => {
          const p = pos(n);
          const r = n.kind === "project" ? 26 : 16;
          const color = NODE_COLOR[n.kind];
          return (
            <g key={n.id} transform={`translate(${p.x} ${p.y})`} className={n.to ? "cursor-pointer" : undefined}
              onClick={() => n.to && navigate(n.to)} role={n.to ? "link" : undefined} tabIndex={n.to ? 0 : undefined}
              onKeyDown={(e) => { if (n.to && (e.key === "Enter" || e.key === " ")) navigate(n.to); }}>
              <circle r={r + 8} fill={`rgb(${color} / 0.12)`} className={!reduce ? "node-pulse" : undefined} style={{ ["--r" as string]: `${r + 8}px` }} />
              <circle r={r} fill={`rgb(${color} / 0.22)`} stroke={`rgb(${color})`} strokeWidth="2" />
              {n.kind === "verified" && <path d="M-6 0 L-2 4 L6 -5" fill="none" stroke={`rgb(${color})`} strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" />}
              {(n.kind === "breached" || n.kind === "exposed") && <path d="M-4 -4 L4 4 M4 -4 L-4 4" stroke={`rgb(${color})`} strokeWidth="2.5" strokeLinecap="round" />}
              <text y={r + 16} textAnchor="middle" className="fill-slate-200 text-[13px] font-medium">{n.label}</text>
              {n.sub && <text y={r + 31} textAnchor="middle" className="fill-slate-500 text-[11px]">{n.sub}</text>}
            </g>
          );
        })}
      </svg>
    </div>
  );
}

export function TopoLegend() {
  const items: [string, NodeKind | "patch"][] = [["Project", "project"], ["Vulnerable", "breached"], ["Patch", "patch"], ["Verified", "verified"], ["Exposed", "exposed"]];
  return (
    <div className="flex flex-wrap gap-x-4 gap-y-1 text-[11px] text-slate-400">
      {items.map(([label, k]) => (
        <span key={label} className="inline-flex items-center gap-1.5">
          <span className="h-2.5 w-2.5 rounded-full" style={{ background: `rgb(${NODE_COLOR[k as NodeKind]})` }} /> {label}
        </span>
      ))}
    </div>
  );
}
