import {
  Activity,
  ArrowUpRight,
  Bot,
  Bug,
  ChevronLeft,
  ChevronRight,
  FileText,
  FlaskConical,
  FolderGit2,
  Gavel,
  LayoutDashboard,
  Menu,
  ScanSearch,
  ShieldCheck,
  X,
} from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { Link, NavLink, Outlet, useLocation } from "react-router-dom";
import { cx } from "../components/ui";
import { useApi } from "../hooks/useApi";
import { api, USE_MOCKS } from "../services/api";

const NAV = [
  { to: "/", label: "Dashboard", icon: LayoutDashboard, end: true },
  { to: "/projects", label: "Projects", icon: FolderGit2 },
  { to: "/court", label: "Fix Court (AI Trial)", icon: Gavel },
  { to: "/scanner", label: "Scanner", icon: ScanSearch },
  { to: "/local-pc", label: "Windows PC", icon: ShieldCheck },
  { to: "/findings", label: "Findings", icon: Bug },
  { to: "/replay", label: "Attack Replay Lab", icon: FlaskConical },
  { to: "/reports", label: "Reports", icon: FileText },
];

export function AppLayout() {
  const [open, setOpen] = useState(false);
  const [collapsed, setCollapsed] = useState(false);
  const sidebar = useRef<HTMLElement>(null);
  const location = useLocation();
  const health = useApi(() => api.health());
  const ai = useApi(() => api.ollamaStatus());
  useEffect(() => {
    setOpen(false);
    window.scrollTo({ top: 0, left: 0, behavior: "instant" });
  }, [location.pathname]);
  useEffect(() => {
    if (!open) return;
    const previousFocus = document.activeElement as HTMLElement | null;
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    sidebar.current?.querySelector<HTMLElement>("a")?.focus();
    const close = (event: KeyboardEvent) => {
      if (event.key === "Escape") setOpen(false);
      if (event.key === "Tab") {
        const items = Array.from(
          sidebar.current?.querySelectorAll<HTMLElement>("a,button") ?? [],
        ).filter((element) => element.getClientRects().length > 0);
        const first = items[0];
        const last = items[items.length - 1];
        if (event.shiftKey && document.activeElement === first) {
          event.preventDefault();
          last?.focus();
        }
        if (!event.shiftKey && document.activeElement === last) {
          event.preventDefault();
          first?.focus();
        }
      }
    };
    document.addEventListener("keydown", close);
    return () => {
      document.removeEventListener("keydown", close);
      document.body.style.overflow = previousOverflow;
      previousFocus?.focus();
    };
  }, [open]);
  const current = NAV.find((n) =>
    n.end ? location.pathname === n.to : location.pathname.startsWith(n.to),
  );
  const title =
    current?.label ??
    (location.pathname.startsWith("/patches")
      ? "Patch review"
      : location.pathname.startsWith("/verification")
        ? "Verification evidence"
        : location.pathname.startsWith("/scans")
          ? "Scan results"
          : "Investigation");
  const connected = health.data?.status === "ok" && !health.error;
  return (
    <div className={cx("command-app", collapsed && "nav-collapsed")}>
      <a href="#main-content" className="skip-link">
        Skip to content
      </a>
      {open && (
        <button
          className="nav-overlay lg:hidden"
          onClick={() => setOpen(false)}
          aria-label="Close navigation"
        />
      )}
      <aside
        ref={sidebar}
        id="workspace-navigation"
        className={cx("command-sidebar", open && "is-open")}
      >
        <Link
          to="/"
          className="command-brand"
          aria-label="PatchProof dashboard"
        >
          <span className="brand-mark">
            <ShieldCheck size={25} strokeWidth={1.6} />
          </span>
          <span className="sidebar-copy">
            <strong>
              Patch<span>Proof</span>
            </strong>
            <small>SECURITY, SUBSTANTIATED.</small>
          </span>
        </Link>
        <button
          className="mobile-close lg:hidden"
          aria-label="Close menu"
          onClick={() => setOpen(false)}
        >
          <X size={18} />
        </button>
        <div className="sidebar-label sidebar-copy">
          WORKSPACE <span>01</span>
        </div>
        <nav aria-label="Main navigation">
          {NAV.map(({ to, label, icon: Icon, end }, index) => (
            <NavLink
              key={to}
              to={to}
              end={end}
              title={collapsed ? label : undefined}
              className={({ isActive }) =>
                cx("command-nav", isActive && "is-active")
              }
            >
              <Icon size={18} strokeWidth={1.6} />
              <span className="sidebar-copy">{label}</span>
              <span className="nav-index sidebar-copy">0{index + 1}</span>
            </NavLink>
          ))}
        </nav>
        <div className="sidebar-mission sidebar-copy">
          <span className="eyebrow">THE PATCHPROOF STANDARD</span>
          <ShieldCheck size={28} />
          <p>
            Find the Flaw.
            <br />
            Challenge the Fix.
            <br />
            <b>Prove It.</b>
          </p>
          <Link to="/replay">
            Open investigation <ArrowUpRight size={14} />
          </Link>
        </div>
        <div className="sidebar-bottom">
          <div className="connection-label">
            <span
              className={cx(
                "status-dot",
                connected && !USE_MOCKS && "connected",
              )}
            />
            <span className="sidebar-copy">
              {USE_MOCKS
                ? "Isolated demo environment"
                : health.error
                  ? "Backend unreachable"
                  : connected
                    ? "Backend connected"
                    : health.loading
                      ? "Checking backend"
                      : "Backend degraded"}
            </span>
          </div>
          <button
            className="collapse-nav hidden lg:flex"
            onClick={() => setCollapsed(!collapsed)}
            aria-label={collapsed ? "Expand navigation" : "Collapse navigation"}
          >
            {collapsed ? <ChevronRight size={16} /> : <ChevronLeft size={16} />}
            <span className="sidebar-copy">Collapse workspace</span>
          </button>
        </div>
      </aside>
      <div className="command-content">
        <header className="command-topbar">
          <div className="flex min-w-0 items-center gap-3">
            <button
              className="lg:hidden"
              aria-label="Open menu"
              aria-expanded={open}
              aria-controls="workspace-navigation"
              onClick={() => setOpen(true)}
            >
              <Menu size={21} />
            </button>
            <div className="breadcrumb">
              <Link to="/">Workspace</Link>
              <ChevronRight size={12} />
              <span>{title}</span>
            </div>
          </div>
          <div className="topbar-signals">
            <span title={health.error?.message ?? health.data?.database}>
              <Activity size={14} />
              {USE_MOCKS
                ? "Demo data"
                : health.error
                  ? "Disconnected"
                  : connected
                    ? "System connected"
                    : health.loading
                      ? "Connecting"
                      : "System degraded"}
            </span>
            <span className="ai-signal" title={ai.data?.message}>
              <Bot size={14} />
              {USE_MOCKS
                ? "AI · demo"
                : ai.error
                  ? "AI unavailable"
                  : ai.data?.available && ai.data.model_installed
                    ? "AI ready"
                    : ai.loading
                      ? "AI checking"
                      : "AI offline"}
            </span>
            <a
              href="https://github.com/diyashivakumar/patcher"
              target="_blank"
              rel="noreferrer"
              aria-label="Open GitHub repository"
            >
              <ArrowUpRight size={17} />
            </a>
          </div>
        </header>
        {USE_MOCKS && (
          <div className="demo-ribbon">
            <span className="status-dot" /> DEMO MODE{" "}
            <span>
              Captured synthetic fixture data · no live security evidence
            </span>
          </div>
        )}
        <main id="main-content" tabIndex={-1} className="command-main">
          <div key={location.pathname} className="page-enter">
            <Outlet />
          </div>
        </main>
        <footer className="command-footer">
          <span>
            PATCHPROOF <span className="text-slate-600">/</span> EVIDENCE OVER
            ASSUMPTION
          </span>
          <span>ISOLATE. REPLAY. VERIFY.</span>
        </footer>
      </div>
    </div>
  );
}
