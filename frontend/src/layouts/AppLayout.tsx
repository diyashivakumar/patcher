import { Bug, FileText, FlaskConical, FolderGit2, LayoutDashboard, Menu, ScanSearch, ShieldCheck, WifiOff, X } from "lucide-react";
import { useState } from "react";
import { NavLink, Outlet } from "react-router-dom";
import { cx } from "../components/ui";
import { useApi } from "../hooks/useApi";
import { API_BASE, api, USE_MOCKS } from "../services/api";

const NAV = [
  { to: "/", label: "Dashboard", icon: LayoutDashboard, end: true },
  { to: "/projects", label: "Projects", icon: FolderGit2 },
  { to: "/scanner", label: "Scanner", icon: ScanSearch },
  { to: "/findings", label: "Findings", icon: Bug },
  { to: "/replay", label: "Attack Replay Lab", icon: FlaskConical },
  { to: "/reports", label: "Reports", icon: FileText },
];

export function AppLayout() {
  const [open, setOpen] = useState(false);
  const health = useApi(() => api.health());
  return (
    <div className="min-h-screen bg-slate-950 text-slate-200">
      {USE_MOCKS && (
        <div className="sticky top-0 z-30 bg-amber-500 px-4 py-1.5 text-center text-xs font-semibold text-slate-950">
          MOCK DATA MODE — responses are canned examples, not real scan or verification results (VITE_USE_MOCKS=true)
        </div>
      )}
      <div className="flex">
        <aside className={cx(
          "fixed inset-y-0 left-0 z-20 flex w-60 flex-col border-r border-slate-800 bg-slate-950 transition-transform lg:sticky lg:top-0 lg:h-screen lg:translate-x-0",
          open ? "translate-x-0" : "-translate-x-full")}>
          <div className="flex items-center gap-2 px-5 py-5">
            <ShieldCheck className="h-6 w-6 text-sky-400" />
            <div>
              <div className="font-semibold text-white">PatchProof</div>
              <div className="text-[11px] text-slate-500">Find the Flaw. Prove the Fix.</div>
            </div>
            <button className="ml-auto lg:hidden" onClick={() => setOpen(false)} aria-label="Close menu"><X className="h-5 w-5" /></button>
          </div>
          <nav className="space-y-1 px-3">
            {NAV.map(({ to, label, icon: Icon, end }) => (
              <NavLink key={to} to={to} end={end} onClick={() => setOpen(false)}
                className={({ isActive }) => cx("flex items-center gap-3 rounded-lg px-3 py-2 text-sm",
                  isActive ? "bg-sky-500/10 text-sky-300" : "text-slate-400 hover:bg-slate-900 hover:text-slate-200")}>
                <Icon className="h-4 w-4" /> {label}
              </NavLink>
            ))}
          </nav>
          <div className="mt-auto border-t border-slate-800 px-5 py-3 text-[11px] text-slate-500">
            API: <span className="break-all font-mono">{USE_MOCKS ? "mock" : API_BASE}</span>
          </div>
        </aside>
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-3 border-b border-slate-800 px-4 py-3 lg:hidden">
            <button onClick={() => setOpen(true)} aria-label="Open menu"><Menu className="h-5 w-5" /></button>
            <span className="font-semibold">PatchProof</span>
          </div>
          {health.error && (
            <div className="flex flex-wrap items-center gap-3 border-b border-rose-500/30 bg-rose-500/10 px-4 py-2.5 text-sm text-rose-200 sm:px-8">
              <WifiOff className="h-4 w-4 shrink-0" />
              <span className="flex-1">Backend unreachable: {health.error.message}</span>
              <button className="rounded-md px-2 py-1 text-rose-100 hover:bg-rose-500/20" onClick={() => void health.reload()} disabled={health.loading}>
                {health.loading ? "Checking…" : "Retry"}
              </button>
            </div>
          )}
          {health.data?.status === "degraded" && (
            <div className="border-b border-amber-500/30 bg-amber-500/10 px-4 py-2.5 text-sm text-amber-200 sm:px-8">
              Backend is up but its database is unavailable ({health.data.database}). Check DATABASE_URL / Neon.
            </div>
          )}
          <main className="mx-auto max-w-7xl px-4 py-6 sm:px-8 sm:py-8">
            <Outlet />
          </main>
        </div>
      </div>
    </div>
  );
}
