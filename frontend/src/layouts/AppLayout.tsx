import { Bot, Bug, Database, FileText, Fingerprint, FlaskConical, FolderGit2, Globe, LayoutDashboard, Link2, Menu, Network, ScanSearch, Swords, WifiOff, X } from "lucide-react";
import { useState } from "react";
import { NavLink, Outlet, useLocation } from "react-router-dom";
import { LogoMark, Wordmark } from "../components/Logo";
import { cx, Pill, ToastHost } from "../components/ui";
import { useApi } from "../hooks/useApi";
import { API_BASE, api, USE_MOCKS } from "../services/api";

const NAV = [
  { to: "/", label: "Dashboard", icon: LayoutDashboard, end: true },
  { to: "/projects", label: "Projects", icon: FolderGit2 },
  { to: "/scanner", label: "Scanner", icon: ScanSearch },
  { to: "/findings", label: "Findings", icon: Bug },
  { to: "/replay", label: "Attack Replay Lab", icon: FlaskConical },
  { to: "/gauntlet", label: "Variant Gauntlet", icon: Swords },
  { to: "/forensics", label: "Exposure Forensics", icon: Fingerprint },
  { to: "/kill-chain", label: "Attack Kill-Chain", icon: Link2 },
  { to: "/host/ports", label: "Port Inspector", icon: Network },
  { to: "/website-check", label: "Website Security", icon: Globe },
  { to: "/reports", label: "Reports", icon: FileText },
];

const CRUMB: Record<string, string> = {
  "": "Dashboard", projects: "Projects", scanner: "Scanner", findings: "Findings",
  scans: "Scan results", replay: "Attack Replay Lab", gauntlet: "Variant Gauntlet", forensics: "Exposure Forensics",
  "kill-chain": "Attack Kill-Chain", host: "Port Inspector", "website-check": "Website Security",
  reports: "Reports", verification: "Verification", patches: "Patch review",
};

function StatusChip({ ok, warn, children }: { ok?: boolean; warn?: boolean; children: React.ReactNode }) {
  return (
    <span className={cx("hidden items-center gap-1.5 rounded-full border px-2.5 py-1 text-[11px] font-medium sm:inline-flex",
      ok ? "border-verified/30 bg-verified/10 text-verified" : warn ? "border-blocked/30 bg-blocked/10 text-blocked" : "border-line/20 bg-surface-2/40 text-slate-400")}>
      {children}
    </span>
  );
}

export function AppLayout() {
  const [open, setOpen] = useState(false);
  const [showDemo, setShowDemo] = useState(true);
  const health = useApi(() => api.health());
  const ollama = useApi(() => api.ollamaStatus());
  const loc = useLocation();
  const seg = loc.pathname.split("/").filter(Boolean)[0] ?? "";
  const crumb = CRUMB[seg] ?? "";
  const dbOk = health.data?.database === "ok" || health.data?.database === "mock";

  return (
    <div className="min-h-screen text-slate-200">
      <div className="flex">
        {open && <div className="fixed inset-0 z-10 bg-black/60 backdrop-blur-sm lg:hidden" onClick={() => setOpen(false)} />}
        <aside className={cx(
          "fixed inset-y-0 left-0 z-20 flex w-64 flex-col border-r border-line/15 bg-ink-2/80 backdrop-blur-xl transition-transform lg:sticky lg:top-0 lg:h-screen lg:translate-x-0",
          open ? "translate-x-0" : "-translate-x-full")}>
          <div className="flex items-center gap-2.5 px-5 py-5">
            <div className="edge-cyan rounded-xl p-1.5"><LogoMark size={28} /></div>
            <Wordmark />
            <button className="ml-auto lg:hidden" onClick={() => setOpen(false)} aria-label="Close menu"><X className="h-5 w-5" /></button>
          </div>
          <div className="px-5 pb-2 text-[10px] font-semibold uppercase tracking-[0.18em] text-slate-600">Command</div>
          <nav className="space-y-0.5 px-3">
            {NAV.map(({ to, label, icon: Icon, end }) => (
              <NavLink key={to} to={to} end={end} onClick={() => setOpen(false)}
                className={({ isActive }) => cx(
                  "group relative flex items-center gap-3 rounded-lg px-3 py-2 text-sm transition-colors",
                  isActive ? "bg-brand/10 text-brand" : "text-slate-400 hover:bg-surface-2/60 hover:text-slate-100")}>
                {({ isActive }: { isActive: boolean }) => (
                  <>
                    <span className={cx("absolute left-0 top-1/2 h-5 w-[3px] -translate-y-1/2 rounded-full transition-all",
                      isActive ? "bg-brand shadow-[0_0_12px_rgb(var(--brand)/0.8)]" : "bg-transparent")} />
                    <Icon className="h-4 w-4" /> {label}
                  </>
                )}
              </NavLink>
            ))}
          </nav>
          <div className="mt-auto border-t border-line/15 px-5 py-3 text-[11px] text-slate-500">
            API <span className="break-all font-mono text-slate-400">{USE_MOCKS ? "demo (mock)" : API_BASE}</span>
          </div>
        </aside>

        <div className="min-w-0 flex-1">
          <header className="sticky top-0 z-10 flex items-center gap-3 border-b border-line/15 bg-ink/70 px-4 py-2.5 backdrop-blur-xl sm:px-8">
            <button className="lg:hidden" onClick={() => setOpen(true)} aria-label="Open menu"><Menu className="h-5 w-5" /></button>
            <nav className="flex items-center gap-1.5 text-sm" aria-label="Breadcrumb">
              <span className="font-semibold text-slate-300">PatchProof</span>
              {crumb && <><span className="text-slate-600">/</span><span className="text-slate-400">{crumb}</span></>}
            </nav>
            <div className="ml-auto flex items-center gap-2">
              <StatusChip ok={dbOk} warn={!dbOk}><Database className="h-3 w-3" /> {health.error ? "offline" : health.data?.database ?? "…"}</StatusChip>
              <StatusChip ok={ollama.data?.model_installed}><Bot className="h-3 w-3" /> AI {ollama.data?.model_installed ? "ready" : "optional"}</StatusChip>
              {USE_MOCKS && showDemo && (
                <Pill className="border-blocked/40 bg-blocked/10 text-blocked ring-0">
                  <span className="h-1.5 w-1.5 rounded-full bg-blocked" /> Demo data
                  <button onClick={() => setShowDemo(false)} aria-label="Dismiss" className="ml-0.5 text-blocked/70 hover:text-blocked"><X className="h-3 w-3" /></button>
                </Pill>
              )}
            </div>
          </header>

          {health.error && (
            <div className="flex flex-wrap items-center gap-3 border-b border-breached/30 bg-breached/10 px-4 py-2.5 text-sm text-rose-200 sm:px-8">
              <WifiOff className="h-4 w-4 shrink-0" />
              <span className="flex-1">Backend unreachable: {health.error.message}</span>
              <button className="rounded-md px-2 py-1 text-rose-100 hover:bg-breached/20" onClick={() => void health.reload()} disabled={health.loading}>
                {health.loading ? "Checking…" : "Retry"}
              </button>
            </div>
          )}
          {health.data?.status === "degraded" && (
            <div className="border-b border-blocked/30 bg-blocked/10 px-4 py-2.5 text-sm text-blocked sm:px-8">
              Backend is up but its database is unavailable ({health.data.database}). Check DATABASE_URL / Neon.
            </div>
          )}

          <main className="mx-auto max-w-[1600px] px-4 py-6 sm:px-8 sm:py-8">
            <Outlet />
          </main>
        </div>
      </div>
      <ToastHost />
    </div>
  );
}
