import { useState } from "react";
import { Link } from "react-router-dom";
import type { Finding, Project, ReportListItem, Severity } from "../types/api";
import { USE_MOCKS } from "../services/api";

const SEVERITIES: { label: Severity; color: string }[] = [
  { label: "CRITICAL", color: "#FF5576" },
  { label: "HIGH", color: "#FFC66D" },
  { label: "MEDIUM", color: "#B66BFF" },
  { label: "LOW", color: "#42E8F5" },
];
export function SeverityChart({
  counts,
}: {
  counts: Record<Severity, number>;
}) {
  const total = Object.values(counts).reduce((sum, n) => sum + n, 0);
  let offset = 0;
  return (
    <div className="severity-chart">
      <svg
        viewBox="0 0 160 160"
        role="img"
        aria-label={`Severity distribution: ${SEVERITIES.map((s) => `${counts[s.label]} ${s.label.toLowerCase()}`).join(", ")}`}
      >
        <circle
          cx="80"
          cy="80"
          r="60"
          fill="none"
          stroke="#1B2A40"
          strokeWidth="12"
        />
        {SEVERITIES.map((s) => {
          const fraction = total ? counts[s.label] / total : 0;
          const start = offset;
          offset += fraction * 100;
          return (
            <circle
              key={s.label}
              cx="80"
              cy="80"
              r="60"
              pathLength="100"
              fill="none"
              stroke={s.color}
              strokeWidth="12"
              strokeDasharray={`${fraction * 100} ${100 - fraction * 100}`}
              strokeDashoffset={-start}
              transform="rotate(-90 80 80)"
              className="chart-arc"
            >
              <title>
                {s.label}: {counts[s.label]}
              </title>
            </circle>
          );
        })}
        <text x="80" y="79" textAnchor="middle" className="donut-value">
          {total}
        </text>
        <text x="80" y="99" textAnchor="middle" className="donut-label">
          FINDINGS
        </text>
      </svg>
      <div className="severity-legend">
        {SEVERITIES.map((s) => (
          <Link key={s.label} to="/findings">
            <span style={{ background: s.color }} />
            <small>{s.label}</small>
            <b>{counts[s.label]}</b>
          </Link>
        ))}
      </div>
    </div>
  );
}

type Node = {
  id: string;
  label: string;
  detail: string;
  x: number;
  y: number;
  color: string;
  href: string;
  parent?: string;
};
export function AttackTopology({
  projects,
  findings,
  reports,
}: {
  projects: Project[];
  findings: Finding[];
  reports: ReportListItem[];
}) {
  const [selected, setSelected] = useState<string | null>(null);
  const nodes: Node[] = [];
  const visibleProjects = projects.slice(0, 3);
  visibleProjects.forEach((p, index) => {
    const y = 90 + index * 140;
    nodes.push({
      id: `project-${p.id}`,
      label: p.name,
      detail: `${p.file_count} source files · ${p.scan_count} scans`,
      x: 110,
      y,
      color: "#42E8F5",
      href: `/projects/${p.id}`,
    });
    const related = findings.filter((f) => f.project_id === p.id).slice(0, 2);
    related.forEach((f, fi) =>
      nodes.push({
        id: `finding-${f.id}`,
        label: f.vuln_type === "sqli" ? "SQL injection" : "Access control",
        detail: `${f.severity} · ${f.file_path}:${f.line_start}`,
        x: 325,
        y: y - 28 + fi * 66,
        color: "#FF5576",
        href: `/findings/${f.id}`,
        parent: `project-${p.id}`,
      }),
    );
    reports
      .filter((r) => r.project_id === p.id)
      .slice(0, 2)
      .forEach((r, ri) => {
        const ry = y - 28 + ri * 66;
        // Report records expose project/patch relationships, but no finding ID. Do not infer one.
        if (r.patch_id)
          nodes.push({
            id: `patch-${r.report_id}`,
            label: "Patch operation",
            detail: r.patch_strategy ?? "Patch evidence",
            x: 535,
            y: ry,
            color: "#B66BFF",
            href: `/patches/${r.patch_id}`,
            parent: `project-${p.id}`,
          });
        nodes.push({
          id: `run-${r.report_id}`,
          label:
            r.kind === "baseline"
              ? "Exploit replay"
              : (r.verdict ?? "No verdict").replace(/_/g, " "),
          detail: `${r.scenario.toUpperCase()} · ${r.status}`,
          x: r.patch_id ? 755 : 535,
          y: ry,
          color:
            r.verdict === "VERIFIED"
              ? "#35E6A1"
              : r.verdict === "FAILED" || r.original_vulnerability_reproduced
                ? "#FF5576"
                : "#42E8F5",
          href: `/verification/${r.report_id}`,
          parent: r.patch_id ? `patch-${r.report_id}` : `project-${p.id}`,
        });
      });
  });
  const selectedNode = nodes.find((n) => n.id === selected);
  const height = Math.max(275, visibleProjects.length * 140 + 40);
  return (
    <div className="topology-shell">
      <div className="topology-caption">
        <span className="eyebrow">
          {USE_MOCKS
            ? "CAPTURED DEMO RELATIONSHIPS"
            : "OBSERVED ENTITY RELATIONSHIPS"}
        </span>
        <span>
          {nodes.length} entities · {visibleProjects.length}/{projects.length}{" "}
          projects
        </span>
      </div>
      {!nodes.length ? (
        <div className="py-16 text-center text-sm text-slate-400">
          Create a project to map your first investigation.
        </div>
      ) : (
        <div className="topology-viewport">
          <svg
            viewBox={`0 0 880 ${height}`}
            style={{ minWidth: 720 }}
            role="group"
            aria-label="Investigation topology. Focus a node for details and activate to open its evidence."
          >
            <defs>
              <pattern
                id="topology-grid"
                width="24"
                height="24"
                patternUnits="userSpaceOnUse"
              >
                <circle cx="1" cy="1" r=".8" fill="#25405B" />
              </pattern>
              <filter id="node-glow">
                <feGaussianBlur stdDeviation="7" />
              </filter>
              <marker
                id="topology-arrow"
                viewBox="0 0 10 10"
                refX="9"
                refY="5"
                markerWidth="5"
                markerHeight="5"
                orient="auto-start-reverse"
              >
                <path d="M0 0 10 5 0 10" fill="#52728A" />
              </marker>
            </defs>
            <rect
              width="880"
              height={height}
              fill="url(#topology-grid)"
              opacity=".55"
            />
            {[110, 325, 535, 755].map((x, i) => (
              <text
                key={x}
                x={x}
                y="25"
                textAnchor="middle"
                className="graph-column"
              >
                {
                  [
                    "SOURCE PROJECT",
                    "VULNERABILITY",
                    "PATCH / REPLAY",
                    "VERIFICATION",
                  ][i]
                }
              </text>
            ))}
            {nodes
              .filter((n) => n.parent)
              .map((n) => {
                const p = nodes.find((parent) => parent.id === n.parent)!;
                return (
                  <path
                    key={`edge-${n.id}`}
                    d={`M${p.x + 21},${p.y} C${p.x + 100},${p.y} ${n.x - 100},${n.y} ${n.x - 24},${n.y}`}
                    fill="none"
                    stroke={n.color}
                    strokeOpacity={
                      selected && selected !== n.id && selected !== p.id
                        ? 0.12
                        : 0.4
                    }
                    strokeWidth="1.3"
                    strokeDasharray="5 5"
                    markerEnd="url(#topology-arrow)"
                    className="topology-edge"
                  />
                );
              })}
            {nodes.map((n) => (
              <Link
                key={n.id}
                to={n.href}
                aria-label={`${n.label}: ${n.detail}. Open evidence.`}
                onFocus={() => setSelected(n.id)}
                onBlur={() => setSelected(null)}
                onMouseEnter={() => setSelected(n.id)}
                onMouseLeave={() => setSelected(null)}
                className="topology-node"
              >
                <title>
                  {n.label}: {n.detail}
                </title>
                <circle
                  cx={n.x}
                  cy={n.y}
                  r="25"
                  fill={n.color}
                  opacity=".15"
                  filter="url(#node-glow)"
                />
                <circle
                  cx={n.x}
                  cy={n.y}
                  r="22"
                  fill="#0B1625"
                  stroke={n.color}
                  strokeOpacity=".5"
                />
                <circle
                  cx={n.x}
                  cy={n.y}
                  r="15"
                  fill={n.color}
                  fillOpacity=".09"
                  stroke={n.color}
                  strokeWidth="1.5"
                />
                <path
                  d={
                    n.id.startsWith("project-")
                      ? `M${n.x - 6},${n.y - 4}h12v10h-12z M${n.x - 3},${n.y - 7}h6`
                      : n.id.startsWith("finding-")
                        ? `M${n.x},${n.y - 7}v8 M${n.x},${n.y + 4}v2`
                        : n.id.startsWith("patch-")
                          ? `M${n.x - 6},${n.y}h12 M${n.x},${n.y - 6}v12`
                          : n.color === "#35E6A1"
                            ? `M${n.x - 5},${n.y}l4,4l7,-8`
                            : `M${n.x - 4},${n.y - 4}l8,8 M${n.x + 4},${n.y - 4}l-8,8`
                  }
                  stroke={n.color}
                  fill="none"
                  strokeWidth="1.5"
                />
                <text
                  x={n.x}
                  y={n.y + 40}
                  textAnchor="middle"
                  className="node-label"
                >
                  {n.label.length > 23 ? `${n.label.slice(0, 21)}…` : n.label}
                </text>
              </Link>
            ))}
          </svg>
        </div>
      )}
      <div className="topology-key">
        <div>
          <span style={{ color: "#42E8F5" }}>● Source</span>
          <span style={{ color: "#FF5576" }}>● Vulnerable</span>
          <span style={{ color: "#B66BFF" }}>● Patch</span>
          <span style={{ color: "#35E6A1" }}>● Verified</span>
        </div>
        <span aria-live="polite">
          {selectedNode
            ? selectedNode.detail
            : "Select a node to investigate →"}
        </span>
      </div>
      <p className="graph-note">
        Edges show recorded relationships, not attack propagation.
        Exposed-record relationships are not available in the current API.
      </p>
    </div>
  );
}
