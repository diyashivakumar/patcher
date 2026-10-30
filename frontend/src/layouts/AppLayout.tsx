import { FileText, FlaskConical, FolderGit2, LayoutDashboard, Menu, ShieldCheck, X } from "lucide-react";
import { useState } from "react";
import { NavLink, Outlet } from "react-router-dom";
import { cx } from "../components/ui";
import { API_BASE, USE_MOCKS } from "../services/api";

const NAV = [
  { to: "/", label: "Dashboard", icon: LayoutDashboard, end: true },
  { to: "/projects", label: "Projects", icon: FolderGit2 },
  { to: "/replay", label: "Attack Replay Lab", icon: FlaskConical },
  { to: "/reports", label: "Reports", icon: FileText },
];

export function AppLayout() {
  const [open, setOpen] = useState(false);
  const location = useLocation();

  return (
    <div className="min-h-screen bg-slate-950 text-slate-200">
      {USE_MOCKS && (
        <div className="sticky top-0 z-50 flex items-center justify-center gap-2 bg-amber-500 px-4 py-1.5 text-center text-xs font-semibold text-slate-950">
          <span className="inline-block h-1.5 w-1.5 rounded-full bg-amber-900 animate-pulse" />
          MOCK DATA — responses are canned examples, not real results (VITE_USE_MOCKS=true)
        </div>
      )}

      {/* Mobile overlay */}
      {open && (
        <div
          className="fixed inset-0 z-10 bg-slate-950/80 backdrop-blur-sm lg:hidden"
          onClick={() => setOpen(false)}
        />
      )}

      <div className="flex">
        {/* ── Sidebar ── */}
        <aside
          className={cx(
            "fixed inset-y-0 left-0 z-20 flex w-60 flex-col border-r border-slate-800/60 bg-slate-950/95 backdrop-blur-xl transition-transform duration-300 lg:sticky lg:top-0 lg:h-screen lg:translate-x-0",
            open ? "translate-x-0" : "-translate-x-full"
          )}
        >
          {/* Logo */}
          <div className="flex items-center gap-3 px-5 py-5">
            <div className="relative flex h-9 w-9 shrink-0 items-center justify-center rounded-xl bg-gradient-to-br from-sky-500 to-indigo-600 shadow-lg shadow-sky-500/20">
              <ShieldCheck className="h-5 w-5 text-white" />
              <div className="absolute inset-0 rounded-xl bg-gradient-to-br from-sky-400/20 to-transparent" />
            </div>
            <div>
              <div className="font-semibold leading-none text-white">PatchProof</div>
              <div className="mt-0.5 text-[10px] tracking-wide text-slate-500">Find the Flaw. Prove the Fix.</div>
            </div>
            <button
              className="ml-auto rounded-lg p-1 text-slate-500 hover:bg-slate-800 hover:text-slate-200 transition lg:hidden"
              onClick={() => setOpen(false)}
              aria-label="Close menu"
            >
              <X className="h-4 w-4" />
            </button>
          </div>

          {/* Divider */}
          <div className="mx-4 h-px bg-gradient-to-r from-transparent via-slate-800 to-transparent" />

          {/* Nav label */}
          <p className="mt-4 px-5 text-[10px] font-semibold uppercase tracking-widest text-slate-600">
            Navigation
          </p>

          {/* Nav links */}
          <nav className="mt-2 space-y-0.5 px-3">
            {NAV.map(({ to, label, icon: Icon, end }) => (
              <NavLink
                key={to}
                to={to}
                end={end}
                onClick={() => setOpen(false)}
                className={({ isActive }) =>
                  cx(
                    "group flex items-center gap-3 rounded-xl px-3 py-2.5 text-sm font-medium transition-all duration-200",
                    isActive
                      ? "bg-sky-500/10 text-sky-300 shadow-[inset_0_0_0_1px_rgba(14,165,233,0.2)]"
                      : "text-slate-400 hover:bg-slate-800/60 hover:text-slate-100"
                  )
                }
              >
                {({ isActive }) => (
                  <>
                    <span
                      className={cx(
                        "flex h-7 w-7 shrink-0 items-center justify-center rounded-lg transition-all",
                        isActive
                          ? "bg-sky-500/20 text-sky-400"
                          : "bg-slate-800/60 text-slate-500 group-hover:bg-slate-700/60 group-hover:text-slate-300"
                      )}
                    >
                      <Icon className="h-4 w-4" />
                    </span>
                    {label}
                    {isActive && (
                      <span className="ml-auto h-1.5 w-1.5 rounded-full bg-sky-400" />
                    )}
                  </>
                )}
              </NavLink>
            ))}
          </nav>

          {/* Footer */}
          <div className="mt-auto">
            <div className="mx-4 h-px bg-gradient-to-r from-transparent via-slate-800 to-transparent" />
            <div className="px-5 py-4">
              <div className="text-[10px] font-semibold uppercase tracking-widest text-slate-600 mb-1">API endpoint</div>
              <div className="break-all font-mono text-[11px] text-slate-500">
                {USE_MOCKS ? "mock" : API_BASE}
              </div>
            </div>
          </div>
        </aside>

        {/* ── Content area ── */}
        <div className="min-w-0 flex-1">
          {/* Mobile topbar */}
          <div className="flex items-center gap-3 border-b border-slate-800/60 bg-slate-950/80 px-4 py-3 backdrop-blur-xl lg:hidden">
            <button
              onClick={() => setOpen(true)}
              className="rounded-lg p-1.5 text-slate-400 hover:bg-slate-800 hover:text-slate-200 transition"
              aria-label="Open menu"
            >
              <Menu className="h-5 w-5" />
            </button>
            <div className="flex items-center gap-2">
              <div className="flex h-6 w-6 items-center justify-center rounded-lg bg-gradient-to-br from-sky-500 to-indigo-600">
                <ShieldCheck className="h-3.5 w-3.5 text-white" />
              </div>
              <span className="font-semibold text-white">PatchProof</span>
            </div>
          </div>

          <main className="mx-auto max-w-7xl px-4 py-6 sm:px-8 sm:py-8 animate-fade-in">
            <Outlet />
          </main>
        </div>
      </div>
    </div>
  );
}
