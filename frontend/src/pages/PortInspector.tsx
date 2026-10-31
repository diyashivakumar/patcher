import { Network, RefreshCw, ShieldAlert, ShieldCheck } from "lucide-react";
import { Button, Card, Empty, ErrorBox, Loading, PageHeader, Pill, Stat } from "../components/ui";
import { useApi } from "../hooks/useApi";
import { api } from "../services/api";
import type { PortEntry, PortRisk } from "../types/api";

const RISK_STYLE: Record<PortRisk, string> = {
  HIGH: "bg-breached/15 text-breached ring-breached/40",
  MEDIUM: "bg-blocked/15 text-blocked ring-blocked/40",
  LOW: "bg-verified/15 text-verified ring-verified/40",
  INFO: "bg-surface-2/60 text-slate-300 ring-line/30",
};

const SCOPE_LABEL: Record<PortEntry["binding_scope"], string> = {
  localhost: "localhost only",
  specific_interface: "specific interface",
  all_interfaces: "all interfaces",
};

export function PortInspector() {
  const ports = useApi(() => api.hostPorts());
  const d = ports.data;

  return (
    <>
      <PageHeader
        title="Windows Port Inspector"
        subtitle="A read-only look at which services are listening on this machine and how widely they are exposed. Nothing is ever terminated, and the firewall is never touched."
        actions={<Button variant="secondary" busy={ports.loading} onClick={() => void ports.reload()}><RefreshCw className="h-4 w-4" /> Rescan</Button>}
      />

      <ErrorBox error={ports.error} onRetry={ports.reload} />
      {ports.loading && !d && <Loading label="Inspecting listening ports…" />}

      {d && !d.supported && (
        <Empty icon={<Network className="h-5 w-5" />}>
          {d.warning ?? `Port Inspector supports Windows only (this host reports "${d.os}").`}
        </Empty>
      )}

      {d && d.supported && (
        <>
          <div className="grid grid-cols-2 gap-4 lg:grid-cols-5">
            <Stat label="Listeners" value={d.summary.total} hint={`${d.summary.tcp} TCP · ${d.summary.udp} UDP`} />
            <Stat label="High risk" value={d.summary.by_risk.HIGH} accent={d.summary.by_risk.HIGH ? "text-breached" : "text-white"} hint="sensitive + public" />
            <Stat label="Medium" value={d.summary.by_risk.MEDIUM} accent={d.summary.by_risk.MEDIUM ? "text-blocked" : "text-white"} hint="network-reachable" />
            <Stat label="Localhost" value={d.summary.localhost} accent="text-verified" hint="not remotely reachable" />
            <Stat label="External" value={d.summary.external} hint="reachable off-box" />
          </div>

          {d.warning && (
            <div className="mt-4 flex items-start gap-2 rounded-lg border border-blocked/30 bg-blocked/10 p-3 text-sm text-blocked">
              <ShieldAlert className="mt-0.5 h-4 w-4 shrink-0" /> {d.warning}
            </div>
          )}

          <Card className="mt-6" title={<span className="inline-flex items-center gap-2"><Network className="h-4 w-4 text-brand" /> Listening ports</span>}
            actions={<span className="text-xs text-slate-500">{d.scope_note}</span>}>
            {d.entries.length === 0 ? (
              <Empty icon={<ShieldCheck className="h-5 w-5" />}>No listening ports were reported.</Empty>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full min-w-[720px] text-left text-sm">
                  <thead className="text-xs uppercase tracking-wide text-slate-500">
                    <tr>
                      <th className="pb-2">Risk</th><th className="pb-2">Proto</th><th className="pb-2">Address : Port</th>
                      <th className="pb-2">Exposure</th><th className="pb-2">Process</th><th className="pb-2">PID</th>
                    </tr>
                  </thead>
                  <tbody>
                    {d.entries.map((e, i) => (
                      <tr key={`${e.protocol}-${e.local_address}-${e.port}-${i}`} className="border-t border-line/10 align-top">
                        <td className="py-2.5"><Pill className={RISK_STYLE[e.risk]}>{e.risk}</Pill></td>
                        <td className="py-2.5 font-mono text-xs text-slate-400">{e.protocol}</td>
                        <td className="py-2.5 font-mono text-xs text-slate-200">{e.local_address}:{e.port ?? "—"}</td>
                        <td className="py-2.5">
                          <div className="text-slate-300">{SCOPE_LABEL[e.binding_scope]}</div>
                          <div className="mt-0.5 max-w-md text-xs text-slate-500">{e.risk_reason}</div>
                        </td>
                        <td className="py-2.5">
                          <div className="text-slate-200">{e.process_name}</div>
                          {e.process_path && <div className="max-w-xs truncate font-mono text-[11px] text-slate-600" title={e.process_path}>{e.process_path}</div>}
                        </td>
                        <td className="py-2.5 tabular-nums text-slate-400">{e.pid ?? "—"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </Card>
          <p className="mt-3 text-xs text-slate-500">
            Risk is a transparent exposure heuristic — how reachable a listener is — not a vulnerability claim. Run as Administrator for complete process details.
          </p>
        </>
      )}
    </>
  );
}
