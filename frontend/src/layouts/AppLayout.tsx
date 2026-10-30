import {
  Bug,
  ChevronRight,
  ExternalLink,
  FileText,
  FlaskConical,
  FolderGit2,
  LayoutDashboard,
  Menu,
  ScanSearch,
  ShieldCheck,
  X,
} from "lucide-react";
import { useState } from "react";
import { Link, NavLink, Outlet, useLocation } from "react-router-dom";
import { cx } from "../components/ui";
import { USE_MOCKS } from "../services/api";

const NAV = [
  { to: "/", label: "Overview", icon: LayoutDashboard, end: true },
  { to: "/projects", label: "Projects", icon: FolderGit2 },
  { to: "/scanner", label: "Code Scanner", icon: ScanSearch },
  { to: "/findings", label: "Findings", icon: Bug },
  { to: "/replay", label: "Attack Replay Lab", icon: FlaskConical },
  { to: "/reports", label: "Verification Reports", icon: FileText },
];

export function AppLayout() {
  const [open, setOpen] = useState(false);
  const location = useLocation();

  // Natural page breadcrumb title
  const currentNav = NAV.find((n) => (n.end ? location.pathname === n.to : location.pathname.startsWith(n.to) && n.to !== "/"));
  const pageTitle = currentNav?.label ?? "Details";

  return (
    <div className="min-h-screen bg-[#0b0e14] text-slate-300">
      {/* Mobile overlay */}
      {open && (
        <div
          className="fixed inset-0 z-40 bg-black/60 backdrop-blur-sm lg:hidden"
          onClick={() => setOpen(false)}
        />
      )}

      <div className="flex">
        {/* ── Sidebar ── */}
        <aside
          className={cx(
            "fixed inset-y-0 left-0 z-50 flex w-64 flex-col border-r border-slate-800/80 bg-[#0d1117] transition-transform duration-200 lg:sticky lg:top-0 lg:h-screen lg:translate-x-0",
            open ? "translate-x-0" : "-translate-x-full"
          )}
        >
          {/* Logo / Workspace */}
          <div className="flex items-center gap-3 border-b border-slate-800/80 px-5 py-4">
            <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-sky-500/10 text-sky-400 border border-sky-500/20">
              <ShieldCheck className="h-5 w-5" />
            </div>
            <div className="min-w-0">
              <div className="text-sm font-semibold tracking-tight text-white flex items-center gap-1.5">
                PatchProof
                <span className="rounded bg-slate-800 px-1 py-0.2 text-[9px] font-mono text-slate-400 font-normal">v0.1</span>
              </div>
              <div className="text-[11px] text-slate-500 truncate">Evidence-based Patch Engine</div>
            </div>
            <button
              className="ml-auto rounded-lg p-1 text-slate-500 hover:bg-slate-800 hover:text-slate-200 transition lg:hidden"
              onClick={() => setOpen(false)}
              aria-label="Close menu"
            >
              <X className="h-4 w-4" />
            </button>
          </div>

          {/* Navigation */}
          <div className="flex-1 overflow-y-auto px-3 py-4">
            <div className="px-3 pb-2 text-[10px] font-semibold uppercase tracking-wider text-slate-500">
              Workspace
            </div>
            <nav className="space-y-1">
              {NAV.map(({ to, label, icon: Icon, end }) => (
                <NavLink
                  key={to}
                  to={to}
                  end={end}
                  onClick={() => setOpen(false)}
                  className={({ isActive }) =>
                    cx(
                      "flex items-center gap-2.5 rounded-lg px-3 py-2 text-xs sm:text-sm font-medium transition-all duration-150",
                      isActive
                        ? "bg-slate-800/90 text-white border border-slate-700/60 shadow-sm"
                        : "text-slate-400 hover:bg-slate-800/40 hover:text-slate-200"
                    )
                  }
                >
                  {({ isActive }) => (
                    <>
                      <Icon
                        className={cx(
                          "h-4 w-4 shrink-0 transition-colors",
                          isActive ? "text-sky-400" : "text-slate-500"
                        )}
                      />
                      <span className="truncate">{label}</span>
                    </>
                  )}
                </NavLink>
              ))}
            </nav>
          </div>

          {/* Sidebar Footer: System Status */}
          <div className="border-t border-slate-800/80 p-3.5 bg-[#0b0e14]/50">
            <div className="flex items-center justify-between text-[11px] text-slate-500">
              <span className="flex items-center gap-1.5 font-medium">
                <span
                  className={cx(
                    "h-2 w-2 rounded-full",
                    USE_MOCKS ? "bg-amber-400" : "bg-emerald-400"
                  )}
                />
                {USE_MOCKS ? "Simulated Sandbox" : "Live Backend"}
              </span>
              <span className="font-mono text-[10px] text-slate-600">
                {USE_MOCKS ? "mock" : ":8000"}
              </span>
            </div>
          </div>
        </aside>

        {/* ── Content area ── */}
        <div className="min-w-0 flex-1 flex flex-col min-h-screen">
          {/* Top navigation bar */}
          <header className="sticky top-0 z-30 flex h-14 items-center justify-between border-b border-slate-800/80 bg-[#0b0e14]/90 px-4 sm:px-8 backdrop-blur-md">
            <div className="flex items-center gap-3">
              <button
                onClick={() => setOpen(true)}
                className="rounded-lg p-1.5 text-slate-400 hover:bg-slate-800 hover:text-slate-200 transition lg:hidden"
                aria-label="Open menu"
              >
                <Menu className="h-5 w-5" />
              </button>
              <div className="flex items-center gap-1.5 text-xs text-slate-400 font-medium">
                <Link to="/" className="hover:text-slate-200 transition">PatchProof</Link>
                <ChevronRight className="h-3.5 w-3.5 text-slate-600" />
                <span className="text-slate-200 font-semibold">{pageTitle}</span>
              </div>
            </div>

            <div className="flex items-center gap-3">
              {USE_MOCKS && (
                <div className="flex items-center gap-1.5 rounded-full border border-amber-500/20 bg-amber-500/10 px-2.5 py-0.5 text-xs font-medium text-amber-300">
                  <span className="h-1.5 w-1.5 rounded-full bg-amber-400" />
                  <span className="hidden sm:inline">Offline Demo Mode</span>
                  <span className="sm:hidden">Demo</span>
                </div>
              )}
              <a
                href="https://github.com/diyashivakumar/patcher"
                target="_blank"
                rel="noreferrer"
                className="flex items-center gap-1.5 text-xs font-medium text-slate-400 hover:text-slate-200 transition"
              >
                <span className="hidden sm:inline">GitHub</span>
                <ExternalLink className="h-3.5 w-3.5" />
              </a>
            </div>
          </header>

          {/* Main content body */}
          <main className="mx-auto w-full max-w-7xl flex-1 px-4 py-6 sm:px-8 sm:py-8 animate-fade-in">
            <Outlet />
          </main>
        </div>
      </div>
    </div>
  );
}
