import { useState } from "react";
import {
  AlertTriangle,
  CheckCircle2,
  Copy,
  Download,
  Globe,
  Lock,
  Monitor,
  RefreshCw,
  Search,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Terminal,
  Unlock,
  X,
  Zap,
} from "lucide-react";
import { Button, Card, ErrorBox, PageHeader, Pill, SeverityBadge } from "../components/ui";
import { API_BASE } from "../services/api";

type PortListener = {
  address: string;
  port: number;
  pid: number;
  process: string;
  binding_type: string;
  is_loopback: boolean;
  has_vulnerability: boolean;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "SAFE";
  service_name: string;
  risk_description: string;
  recommendation: string;
  rule_name: string;
};

type PortInventory = {
  captured_at: string;
  scope: string;
  total_listeners: number;
  exposed_listeners: number;
  vulnerable_listeners: number;
  ports: PortListener[];
};

type LiveScanResult = {
  target_url: string;
  scanned_at: string;
  status_code: number;
  latency_ms: number;
  server_banner: string;
  grade: string;
  headers_audit: Record<string, { status: "PASS" | "FAIL" | "INFO"; value: string | null }>;
  exposed_endpoints: { path: string; url: string; status: number; description: string; severity: string }[];
  findings_count: number;
  severity_counts: Record<string, number>;
  findings: {
    id: string;
    title: string;
    severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
    cwe: string;
    impact: string;
    evidence: string;
    remediation: string;
    code_fix: string;
  }[];
};

type RemediationData = {
  port: number;
  action: string;
  rule_name: string;
  powershell_script: string;
  rollback_script: string;
  filename: string;
};

export function LocalPC() {
  const [activeTab, setActiveTab] = useState<"ports" | "live_scan">("ports");

  // Port Inventory State
  const [data, setData] = useState<PortInventory | null>(null);
  const [error, setError] = useState<Error | null>(null);
  const [busy, setBusy] = useState(false);
  const [search, setSearch] = useState("");
  const [filterVulnerable, setFilterVulnerable] = useState(false);

  // Remediation Drawer State
  const [selectedPort, setSelectedPort] = useState<PortListener | null>(null);
  const [remediation, setRemediation] = useState<RemediationData | null>(null);
  const [confirmed, setConfirmed] = useState(false);
  const [copiedScript, setCopiedScript] = useState(false);
  const [copiedRollback, setCopiedRollback] = useState(false);
  const [notice, setNotice] = useState("");

  // Live Website / Server Scanner State
  const [targetUrl, setTargetUrl] = useState("http://localhost:8000");
  const [liveBusy, setLiveBusy] = useState(false);
  const [liveError, setLiveError] = useState<Error | null>(null);
  const [liveResult, setLiveResult] = useState<LiveScanResult | null>(null);

  // Fetch Live Windows Ports
  const inspectPorts = async () => {
    setBusy(true);
    setError(null);
    setSelectedPort(null);
    setRemediation(null);
    try {
      const response = await fetch(`${API_BASE}/local-pc/ports`);
      const body = await response.json();
      if (!response.ok) throw new Error(body.detail ?? body.error?.message ?? "Unable to inspect Windows PC ports.");
      setData(body);
      setNotice("Live Windows listeners refreshed. Active vulnerabilities analyzed.");
    } catch (e) {
      setError(e instanceof Error ? e : new Error("Port inspection failed"));
    } finally {
      setBusy(false);
    }
  };

  // Open Remediation Review
  const prepareRemediation = async (port: PortListener, action: "block" | "allow" | "stop_process") => {
    setSelectedPort(port);
    setConfirmed(false);
    try {
      const res = await fetch(`${API_BASE}/local-pc/ports/remediate`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ port: port.port, action, protocol: "TCP" }),
      });
      const body = await res.json();
      if (!res.ok) throw new Error(body.detail ?? "Failed to prepare remediation script.");
      setRemediation(body);
    } catch (e) {
      setError(e instanceof Error ? e : new Error("Failed to prepare remediation."));
    }
  };

  // Download PowerShell Remediation
  const downloadScript = () => {
    if (!remediation) return;
    const blob = new Blob([remediation.powershell_script], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = remediation.filename;
    link.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    setNotice(`Downloaded ${remediation.filename}. Run it in an elevated Administrator PowerShell prompt to apply.`);
  };

  const copyScript = (text: string, isRollback: boolean) => {
    navigator.clipboard.writeText(text);
    if (isRollback) {
      setCopiedRollback(true);
      setTimeout(() => setCopiedRollback(false), 2000);
    } else {
      setCopiedScript(true);
      setTimeout(() => setCopiedScript(false), 2000);
    }
  };

  // Run Live Website / Server Scan
  const runLiveScan = async () => {
    if (!targetUrl.trim()) return;
    setLiveBusy(true);
    setLiveError(null);
    try {
      const res = await fetch(`${API_BASE}/local-pc/live-scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target_url: targetUrl.trim(), probe_endpoints: true }),
      });
      const body = await res.json();
      if (!res.ok) throw new Error(body.detail ?? "Live scan failed to connect to target.");
      setLiveResult(body);
    } catch (e) {
      setLiveError(e instanceof Error ? e : new Error("Live scan failed."));
    } finally {
      setLiveBusy(false);
    }
  };

  // Filter Ports
  const filteredPorts =
    data?.ports.filter((p) => {
      const matchesSearch = `${p.port} ${p.process} ${p.address} ${p.service_name} ${p.risk_description}`
        .toLowerCase()
        .includes(search.toLowerCase());
      if (filterVulnerable) return matchesSearch && p.has_vulnerability;
      return matchesSearch;
    }) ?? [];

  return (
    <div className="space-y-6 animate-fade-in">
      <PageHeader
        title="Live Host & Network Security Center"
        subtitle="Inspect real ports on this Windows PC, remediate open port vulnerabilities, and audit live servers with real data."
        actions={
          <div className="flex items-center gap-2">
            <div className="flex rounded-lg border border-slate-800 bg-[#10141d] p-1">
              <button
                onClick={() => setActiveTab("ports")}
                className={`flex items-center gap-2 rounded-md px-3 py-1.5 text-xs font-semibold transition ${
                  activeTab === "ports"
                    ? "bg-slate-800 text-white shadow-sm border border-slate-700/60"
                    : "text-slate-400 hover:text-slate-200"
                }`}
              >
                <Monitor className="h-3.5 w-3.5 text-sky-400" />
                Windows Port Security
              </button>
              <button
                onClick={() => setActiveTab("live_scan")}
                className={`flex items-center gap-2 rounded-md px-3 py-1.5 text-xs font-semibold transition ${
                  activeTab === "live_scan"
                    ? "bg-slate-800 text-white shadow-sm border border-slate-700/60"
                    : "text-slate-400 hover:text-slate-200"
                }`}
              >
                <Globe className="h-3.5 w-3.5 text-emerald-400" />
                Live Website / Server Audit
              </button>
            </div>
          </div>
        }
      />

      {notice && (
        <div className="flex items-center justify-between rounded-xl border border-sky-500/30 bg-sky-500/10 px-4 py-3 text-xs sm:text-sm text-sky-300">
          <div className="flex items-center gap-2">
            <ShieldCheck className="h-4 w-4 shrink-0 text-sky-400" />
            <span>{notice}</span>
          </div>
          <button onClick={() => setNotice("")} className="text-sky-400 hover:text-white">
            <X className="h-4 w-4" />
          </button>
        </div>
      )}

      {/* ── TAB 1: WINDOWS PC PORT SECURITY ── */}
      {activeTab === "ports" && (
        <div className="space-y-6">
          <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between rounded-xl border border-slate-800/80 bg-[#10141d]/80 p-5">
            <div>
              <h2 className="text-sm font-semibold text-white flex items-center gap-2">
                <Shield className="h-4 w-4 text-sky-400" />
                Real-Time Windows Listener & Port Vulnerability Scanner
              </h2>
              <p className="mt-1 text-xs text-slate-400 max-w-2xl leading-relaxed">
                Queries real TCP connections directly from your Windows operating system via PowerShell/netstat.
                Flags exposed database ports, unencrypted remote administration (RDP, WinRM, SMB), and lets you apply
                tested Windows Firewall blocks with rollback.
              </p>
            </div>
            <Button busy={busy} onClick={inspectPorts} className="gap-2 shrink-0">
              <RefreshCw className="h-4 w-4" />
              Scan Windows Ports
            </Button>
          </div>

          <ErrorBox error={error} onRetry={inspectPorts} />

          {data && (
            <>
              {/* Telemetry Stats */}
              <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
                <div className="rounded-xl border border-slate-800/80 bg-[#10141d]/80 p-4">
                  <div className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">Total Listeners</div>
                  <div className="mt-2 text-2xl font-bold tracking-tight text-white">{data.total_listeners}</div>
                  <div className="mt-1 text-[11px] text-slate-500">Active TCP sockets</div>
                </div>
                <div className="rounded-xl border border-slate-800/80 bg-[#10141d]/80 p-4">
                  <div className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">Exposed (0.0.0.0)</div>
                  <div className="mt-2 text-2xl font-bold tracking-tight text-amber-400">{data.exposed_listeners}</div>
                  <div className="mt-1 text-[11px] text-slate-500">Bound to network interfaces</div>
                </div>
                <div className="rounded-xl border border-slate-800/80 bg-[#10141d]/80 p-4">
                  <div className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">Vulnerabilities</div>
                  <div className="mt-2 text-2xl font-bold tracking-tight text-rose-400">{data.vulnerable_listeners}</div>
                  <div className="mt-1 text-[11px] text-slate-500">High-risk sensitive ports exposed</div>
                </div>
                <div className="rounded-xl border border-slate-800/80 bg-[#10141d]/80 p-4">
                  <div className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">Loopback Safe</div>
                  <div className="mt-2 text-2xl font-bold tracking-tight text-emerald-400">
                    {data.total_listeners - data.exposed_listeners}
                  </div>
                  <div className="mt-1 text-[11px] text-slate-500">Bound to 127.0.0.1 (isolated)</div>
                </div>
              </div>

              {/* Port Table Card */}
              <Card
                title={
                  <div className="flex items-center gap-2">
                    <Monitor className="h-4 w-4 text-sky-400" />
                    <span>Active Port Listeners ({filteredPorts.length})</span>
                  </div>
                }
                subtitle={`Snapshot captured at ${new Date(data.captured_at).toLocaleTimeString()}`}
                actions={
                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => setFilterVulnerable(!filterVulnerable)}
                      className={`rounded-lg px-2.5 py-1 text-xs font-medium border transition ${
                        filterVulnerable
                          ? "bg-rose-500/20 text-rose-300 border-rose-500/40"
                          : "bg-slate-800 text-slate-400 border-slate-700 hover:text-slate-200"
                      }`}
                    >
                      {filterVulnerable ? "Showing Vulnerabilities" : "Filter Vulnerabilities"}
                    </button>
                  </div>
                }
              >
                {/* Search Bar */}
                <div className="mb-4 relative">
                  <Search className="h-4 w-4 absolute left-3 top-2.5 text-slate-500" />
                  <input
                    className="w-full rounded-lg border border-slate-800 bg-[#0d1117] pl-9 pr-3 py-2 text-xs sm:text-sm text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-sky-500"
                    placeholder="Search by port number, process name, service, or IP address..."
                    value={search}
                    onChange={(e) => setSearch(e.target.value)}
                  />
                </div>

                <div className="overflow-x-auto">
                  <table className="w-full min-w-[750px] text-left text-xs sm:text-sm">
                    <thead>
                      <tr className="border-b border-slate-800/80 text-[11px] font-semibold uppercase tracking-wider text-slate-500">
                        <th className="pb-3">Port & Protocol</th>
                        <th className="pb-3">Process & PID</th>
                        <th className="pb-3">Service & Risk</th>
                        <th className="pb-3">Network Exposure</th>
                        <th className="pb-3 text-right">Fix Action</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/60 font-mono text-xs">
                      {filteredPorts.map((p) => (
                        <tr
                          key={`${p.address}:${p.port}:${p.pid}`}
                          className={`group hover:bg-slate-800/30 transition-colors ${
                            p.has_vulnerability ? "bg-rose-500/5" : ""
                          }`}
                        >
                          <td className="py-3.5">
                            <div className="flex items-center gap-2 font-semibold text-white">
                              {p.has_vulnerability ? (
                                <AlertTriangle className="h-3.5 w-3.5 text-rose-400 shrink-0" />
                              ) : p.is_loopback ? (
                                <Lock className="h-3.5 w-3.5 text-emerald-400 shrink-0" />
                              ) : (
                                <Unlock className="h-3.5 w-3.5 text-amber-400 shrink-0" />
                              )}
                              <span>TCP {p.port}</span>
                            </div>
                            <span className="text-[11px] text-slate-500 block mt-0.5">{p.address}</span>
                          </td>
                          <td className="py-3.5">
                            <span className="text-slate-200 font-sans font-medium">{p.process}</span>
                            <span className="text-[11px] text-slate-500 block">PID {p.pid}</span>
                          </td>
                          <td className="py-3.5 max-w-xs font-sans">
                            <div className="flex items-center gap-2">
                              <span className="text-xs font-semibold text-slate-300">{p.service_name}</span>
                              {p.has_vulnerability && (
                                <span className="rounded bg-rose-500/20 text-rose-300 px-1.5 py-0.2 text-[10px] font-bold">
                                  {p.severity}
                                </span>
                              )}
                            </div>
                            <p className="text-[11px] text-slate-400 mt-0.5 line-clamp-1">{p.risk_description}</p>
                          </td>
                          <td className="py-3.5 font-sans">
                            <Pill
                              className={
                                p.is_loopback
                                  ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-400"
                                  : "border-amber-500/30 bg-amber-500/10 text-amber-300"
                              }
                            >
                              <span className="h-1.5 w-1.5 rounded-full bg-current" />
                              {p.binding_type}
                            </Pill>
                          </td>
                          <td className="py-3.5 text-right font-sans">
                            <div className="inline-flex items-center gap-1.5">
                              <Button
                                variant={p.has_vulnerability ? "danger" : "secondary"}
                                onClick={() => prepareRemediation(p, "block")}
                                className="h-7 text-xs px-2.5 gap-1.5"
                                title="Block inbound traffic to this port via Windows Defender Firewall"
                              >
                                <Lock className="h-3 w-3" />
                                Close / Block Port
                              </Button>
                              <Button
                                variant="ghost"
                                onClick={() => prepareRemediation(p, "allow")}
                                className="h-7 text-xs px-2 text-slate-400 hover:text-slate-200"
                                title="Create allow rule"
                              >
                                <Unlock className="h-3 w-3" />
                              </Button>
                            </div>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                  {!filteredPorts.length && (
                    <div className="py-8 text-center text-xs text-slate-500">
                      No port listeners match your search or filter.
                    </div>
                  )}
                </div>
              </Card>
            </>
          )}

          {/* Remediation Drawer / Review Modal */}
          {selectedPort && remediation && (
            <Card
              className="border-sky-500/40 bg-[#10141d] shadow-lg"
              title={
                <div className="flex items-center justify-between w-full">
                  <div className="flex items-center gap-2">
                    <ShieldAlert className="h-4 w-4 text-sky-400" />
                    <span>Review Port Remediation · TCP {selectedPort.port}</span>
                  </div>
                  <button onClick={() => setSelectedPort(null)} className="text-slate-500 hover:text-slate-300">
                    <X className="h-4 w-4" />
                  </button>
                </div>
              }
              subtitle={`Target service: ${selectedPort.service_name} (${selectedPort.process}, PID ${selectedPort.pid})`}
            >
              <div className="space-y-4">
                <div className="rounded-lg bg-slate-900/80 p-3.5 border border-slate-800 text-xs text-slate-300 leading-relaxed">
                  <p className="font-semibold text-white mb-1">Vulnerability Impact:</p>
                  <p>{selectedPort.risk_description}</p>
                  <p className="mt-2 text-slate-400 font-sans">
                    <strong>Remediation Strategy:</strong> {selectedPort.recommendation}
                  </p>
                </div>

                <div>
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-[11px] font-bold uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
                      <Terminal className="h-3.5 w-3.5 text-sky-400" />
                      Windows Defender Firewall Command
                    </span>
                    <button
                      onClick={() => copyScript(remediation.powershell_script, false)}
                      className="text-xs text-sky-400 hover:text-sky-300 inline-flex items-center gap-1 font-sans"
                    >
                      {copiedScript ? <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400" /> : <Copy className="h-3.5 w-3.5" />}
                      {copiedScript ? "Copied" : "Copy PowerShell"}
                    </button>
                  </div>
                  <pre className="overflow-x-auto rounded-lg bg-slate-950 p-3.5 font-mono text-xs text-slate-300 border border-slate-800 leading-5 max-h-48">
                    {remediation.powershell_script}
                  </pre>
                </div>

                <div>
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-[11px] font-bold uppercase tracking-wider text-slate-400">
                      Verified Rollback Script
                    </span>
                    <button
                      onClick={() => copyScript(remediation.rollback_script, true)}
                      className="text-xs text-slate-400 hover:text-slate-200 inline-flex items-center gap-1 font-sans"
                    >
                      {copiedRollback ? <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400" /> : <Copy className="h-3.5 w-3.5" />}
                      {copiedRollback ? "Copied" : "Copy Rollback"}
                    </button>
                  </div>
                  <pre className="overflow-x-auto rounded-lg bg-slate-950 p-3.5 font-mono text-xs text-slate-400 border border-slate-800 leading-5">
                    {remediation.rollback_script}
                  </pre>
                </div>

                <label className="flex items-start gap-3 cursor-pointer pt-2">
                  <input
                    type="checkbox"
                    checked={confirmed}
                    onChange={(e) => setConfirmed(e.target.checked)}
                    className="mt-0.5 rounded border-slate-700 bg-slate-900 text-sky-500 focus:ring-0"
                  />
                  <span className="text-xs text-slate-300 leading-relaxed font-sans">
                    I confirm that I reviewed this service ({selectedPort.process}) and want to apply this firewall remediation rule.
                  </span>
                </label>

                <div className="flex flex-wrap items-center gap-3 pt-2">
                  <Button disabled={!confirmed} onClick={downloadScript} className="gap-2">
                    <Download className="h-4 w-4" />
                    Download PowerShell Fix (.ps1)
                  </Button>
                  <Button variant="ghost" onClick={() => setSelectedPort(null)}>
                    Cancel
                  </Button>
                </div>
              </div>
            </Card>
          )}

          {!data && !busy && (
            <div className="rounded-xl border border-dashed border-slate-800 p-12 text-center">
              <Monitor className="h-8 w-8 text-slate-600 mx-auto mb-3" />
              <h3 className="text-sm font-semibold text-slate-300">No Port Scan Active</h3>
              <p className="mt-1 text-xs text-slate-500 max-w-sm mx-auto">
                Click "Scan Windows Ports" above to retrieve live listener telemetry from your Windows PC.
              </p>
            </div>
          )}
        </div>
      )}

      {/* ── TAB 2: LIVE WEBSITE & SERVER SECURITY AUDIT (REAL DATA) ── */}
      {activeTab === "live_scan" && (
        <div className="space-y-6">
          <Card
            title={
              <div className="flex items-center gap-2">
                <Globe className="h-4 w-4 text-emerald-400" />
                <span>Connect Live Website / Server for Real Security Testing</span>
              </div>
            }
            subtitle="Send live HTTP probes against any local or remote server endpoint to audit security headers, sensitive leaks, and exposed admin interfaces."
          >
            <div className="space-y-4">
              <div className="flex flex-col sm:flex-row gap-3">
                <input
                  type="text"
                  value={targetUrl}
                  onChange={(e) => setTargetUrl(e.target.value)}
                  placeholder="e.g. http://localhost:8000 or https://your-server.com"
                  className="flex-1 rounded-lg border border-slate-700/80 bg-slate-900 px-3.5 py-2.5 text-xs sm:text-sm text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-emerald-500 font-mono"
                />
                <Button busy={liveBusy} onClick={runLiveScan} className="bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-semibold gap-2 shrink-0">
                  <Zap className="h-4 w-4" />
                  Audit Live Target
                </Button>
              </div>

              <div className="flex items-center gap-2 text-xs text-slate-500">
                <span>Quick presets:</span>
                <button
                  type="button"
                  onClick={() => setTargetUrl("http://localhost:8000")}
                  className="text-sky-400 hover:underline"
                >
                  Local API (:8000)
                </button>
                <span>·</span>
                <button
                  type="button"
                  onClick={() => setTargetUrl("http://localhost:5173")}
                  className="text-sky-400 hover:underline"
                >
                  Frontend (:5173)
                </button>
                <span>·</span>
                <button
                  type="button"
                  onClick={() => setTargetUrl("https://example.com")}
                  className="text-sky-400 hover:underline"
                >
                  External HTTPS
                </button>
              </div>
            </div>
          </Card>

          <ErrorBox error={liveError} onRetry={runLiveScan} />

          {liveResult && (
            <div className="space-y-6">
              {/* Score & Target Summary Banner */}
              <div className="rounded-xl border border-slate-800 bg-[#10141d] p-5">
                <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
                  <div className="flex items-center gap-4">
                    <div
                      className={`flex h-14 w-14 items-center justify-center rounded-xl font-bold text-2xl font-mono shadow-sm ${
                        liveResult.grade.startsWith("A")
                          ? "bg-emerald-500/20 text-emerald-400 border border-emerald-500/40"
                          : liveResult.grade.startsWith("B") || liveResult.grade.startsWith("C")
                          ? "bg-amber-500/20 text-amber-400 border border-amber-500/40"
                          : "bg-rose-500/20 text-rose-400 border border-rose-500/40"
                      }`}
                    >
                      {liveResult.grade}
                    </div>
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="font-semibold text-white text-base">{liveResult.target_url}</span>
                        <Pill className="border-slate-700 bg-slate-800 text-slate-300 font-mono text-[11px]">
                          HTTP {liveResult.status_code}
                        </Pill>
                      </div>
                      <div className="flex items-center gap-3 mt-1 text-xs text-slate-400">
                        <span>Latency: {liveResult.latency_ms}ms</span>
                        <span>·</span>
                        <span>Server: {liveResult.server_banner}</span>
                      </div>
                    </div>
                  </div>

                  <div className="flex items-center gap-2 text-xs">
                    {liveResult.severity_counts.CRITICAL > 0 && (
                      <span className="rounded bg-rose-500/20 text-rose-300 px-2.5 py-1 font-bold">
                        {liveResult.severity_counts.CRITICAL} Critical
                      </span>
                    )}
                    {liveResult.severity_counts.HIGH > 0 && (
                      <span className="rounded bg-orange-500/20 text-orange-300 px-2.5 py-1 font-bold">
                        {liveResult.severity_counts.HIGH} High
                      </span>
                    )}
                    {liveResult.severity_counts.MEDIUM > 0 && (
                      <span className="rounded bg-amber-500/20 text-amber-300 px-2.5 py-1 font-bold">
                        {liveResult.severity_counts.MEDIUM} Medium
                      </span>
                    )}
                    {liveResult.findings_count === 0 && (
                      <span className="rounded bg-emerald-500/20 text-emerald-300 px-2.5 py-1 font-bold">
                        Zero Vulnerabilities Detected
                      </span>
                    )}
                  </div>
                </div>
              </div>

              {/* Security Headers Checklist */}
              <Card title="HTTP Security Headers Audit" subtitle="Evaluates browser defense flags against clickjacking, sniffing, and XSS">
                <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
                  {Object.entries(liveResult.headers_audit).map(([header, check]) => (
                    <div
                      key={header}
                      className="rounded-lg border border-slate-800 bg-[#0d1117] p-3 flex items-start justify-between gap-2"
                    >
                      <div className="min-w-0">
                        <div className="font-mono text-xs font-semibold text-slate-200 truncate">{header}</div>
                        <div className="text-[11px] text-slate-500 truncate mt-0.5 font-mono">
                          {check.value || "Not Set"}
                        </div>
                      </div>
                      <span
                        className={`rounded px-1.5 py-0.5 text-[10px] font-bold uppercase shrink-0 ${
                          check.status === "PASS"
                            ? "bg-emerald-500/20 text-emerald-400"
                            : check.status === "FAIL"
                            ? "bg-rose-500/20 text-rose-400"
                            : "bg-slate-800 text-slate-400"
                        }`}
                      >
                        {check.status}
                      </span>
                    </div>
                  ))}
                </div>
              </Card>

              {/* Exposed Endpoints Probed */}
              {liveResult.exposed_endpoints.length > 0 && (
                <Card
                  title="Sensitive Exposed Endpoints"
                  subtitle="Endpoints successfully probed and responding with public HTTP 200/300 status"
                >
                  <div className="divide-y divide-slate-800 font-mono text-xs">
                    {liveResult.exposed_endpoints.map((ep) => (
                      <div key={ep.path} className="flex items-center justify-between py-2.5">
                        <div className="flex items-center gap-2">
                          <span className="text-white font-semibold">{ep.path}</span>
                          <span className="text-slate-500 font-sans">({ep.description})</span>
                        </div>
                        <div className="flex items-center gap-2">
                          <Pill className="border-slate-700 bg-slate-800 text-slate-300">HTTP {ep.status}</Pill>
                          <span
                            className={`rounded px-1.5 py-0.5 text-[10px] font-bold ${
                              ep.severity === "CRITICAL"
                                ? "bg-rose-500/20 text-rose-400"
                                : "bg-sky-500/20 text-sky-400"
                            }`}
                          >
                            {ep.severity}
                          </span>
                        </div>
                      </div>
                    ))}
                  </div>
                </Card>
              )}

              {/* Real Findings & Code Fixes */}
              <Card
                title={`Live Vulnerabilities Detected (${liveResult.findings.length})`}
                subtitle="Identified security flaws with copy-paste defensive patches"
              >
                <div className="space-y-4">
                  {liveResult.findings.map((f) => (
                    <div
                      key={f.id}
                      className="rounded-xl border border-slate-800 bg-[#0d1117] p-4 space-y-3"
                    >
                      <div className="flex items-start justify-between gap-3">
                        <div>
                          <div className="flex items-center gap-2">
                            <h4 className="font-semibold text-sm text-slate-200">{f.title}</h4>
                            <span className="text-xs text-slate-500 font-mono">({f.cwe})</span>
                          </div>
                          <p className="mt-1 text-xs text-slate-400 leading-relaxed">{f.impact}</p>
                        </div>
                        <SeverityBadge severity={f.severity} />
                      </div>

                      <div className="rounded-lg bg-slate-900/90 p-3 border border-slate-800 text-xs">
                        <div className="text-slate-400 mb-1">
                          <strong>Evidence:</strong> <span className="font-mono text-slate-300">{f.evidence}</span>
                        </div>
                        <div className="text-slate-400 mb-2">
                          <strong>Remediation:</strong> {f.remediation}
                        </div>
                        <div className="font-mono text-[11px] text-emerald-300 bg-slate-950 p-2.5 rounded border border-slate-800/80 overflow-x-auto">
                          {f.code_fix}
                        </div>
                      </div>
                    </div>
                  ))}

                  {liveResult.findings.length === 0 && (
                    <div className="py-8 text-center text-xs text-slate-500">
                      Great job! No standard HTTP misconfigurations or header leaks were detected on this target.
                    </div>
                  )}
                </div>
              </Card>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
