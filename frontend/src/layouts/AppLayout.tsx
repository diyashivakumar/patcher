import { Bot, Bug, Database, FileText, Fingerprint, FlaskConical, FolderGit2, Github, Globe, LayoutDashboard, Link2, Menu, Moon, Network, ScanSearch, Sun, Swords, WifiOff, X } from "lucide-react";
import { Suspense, useState } from "react";
import { NavLink, Outlet, useLocation } from "react-router-dom";
import { LogoMark, Wordmark } from "../components/Logo";
import { cx, Loading, Pill, ToastHost } from "../components/ui";
import { useI18n } from "../i18n";
import type { TranslationKey } from "../i18n/en";
import { API_BASE, USE_MOCKS } from "../services/api";
import { useStatus } from "../status";
import { useTheme } from "../theme";

const NAV: { to: string; key: TranslationKey; icon: typeof Bug; end?: boolean }[] = [
  { to: "/", key: "nav.dashboard", icon: LayoutDashboard, end: true },
  { to: "/projects", key: "nav.projects", icon: FolderGit2 },
  { to: "/import/github", key: "nav.githubImport", icon: Github },
  { to: "/scanner", key: "nav.scanner", icon: ScanSearch },
  { to: "/findings", key: "nav.findings", icon: Bug },
  { to: "/replay", key: "nav.replay", icon: FlaskConical },
  { to: "/gauntlet", key: "nav.gauntlet", icon: Swords },
  { to: "/forensics", key: "nav.forensics", icon: Fingerprint },
  { to: "/kill-chain", key: "nav.killChain", icon: Link2 },
  { to: "/host/ports", key: "nav.portInspector", icon: Network },
  { to: "/website-check", key: "nav.websiteSecurity", icon: Globe },
  { to: "/reports", key: "nav.reports", icon: FileText },
];

const CRUMB_KEY: Record<string, TranslationKey> = {
  "": "nav.dashboard", projects: "nav.projects", import: "nav.githubImport", scanner: "nav.scanner",
  findings: "nav.findings", replay: "nav.replay", gauntlet: "nav.gauntlet", forensics: "nav.forensics",
  "kill-chain": "nav.killChain", host: "nav.portInspector", "website-check": "nav.websiteSecurity", reports: "nav.reports",
};
const CRUMB_EN: Record<string, string> = { scans: "Scan results", verification: "Verification", patches: "Patch review" };

function StatusChip({ ok, warn, children }: { ok?: boolean; warn?: boolean; children: React.ReactNode }) {
  return (
    <span className={cx("hidden items-center gap-1.5 rounded-full border px-2.5 py-1 text-[11px] font-medium sm:inline-flex",
      ok ? "border-verified/30 bg-verified/10 text-verified" : warn ? "border-blocked/30 bg-blocked/10 text-blocked" : "border-line/20 bg-surface-2/40 text-slate-400")}>
      {children}
    </span>
  );
}

function ThemeToggle() {
  const { theme, toggle } = useTheme();
  const { t } = useI18n();
  const dark = theme === "dark";
  return (
    <button
      onClick={toggle}
      aria-label={`${t("header.theme")}: ${dark ? t("header.themeDark") : t("header.themeLight")}`}
      title={dark ? t("header.themeLight") : t("header.themeDark")}
      className="inline-flex h-8 w-8 items-center justify-center rounded-lg border border-line/20 bg-surface-2/50 text-slate-300 transition-colors hover:border-brand/40 hover:text-brand"
    >
      {dark ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
    </button>
  );
}

export function AppLayout() {
  const [open, setOpen] = useState(false);
  const [showDemo, setShowDemo] = useState(true);
  const { health, ollama } = useStatus();
  const { t } = useI18n();
  const loc = useLocation();
  const seg = loc.pathname.split("/").filter(Boolean)[0] ?? "";
  const crumb = CRUMB_KEY[seg] ? t(CRUMB_KEY[seg]) : CRUMB_EN[seg] ?? "";
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
            <button className="ml-auto lg:hidden" onClick={() => setOpen(false)} aria-label={t("header.closeMenu")}><X className="h-5 w-5" /></button>
          </div>
          <div className="px-5 pb-2 text-[10px] font-semibold uppercase tracking-[0.18em] text-slate-600">{t("nav.command")}</div>
          <nav className="space-y-0.5 px-3 pb-4 overflow-y-auto">
            {NAV.map(({ to, key, icon: Icon, end }) => (
              <NavLink key={to} to={to} end={end} onClick={() => setOpen(false)}
                className={({ isActive }) => cx(
                  "group relative flex items-center gap-3 rounded-lg px-3 py-2 text-sm transition-colors",
                  isActive ? "bg-brand/10 text-brand" : "text-slate-400 hover:bg-surface-2/60 hover:text-slate-100")}>
                {({ isActive }: { isActive: boolean }) => (
                  <>
                    <span className={cx("absolute left-0 top-1/2 h-5 w-[3px] -translate-y-1/2 rounded-full transition-all",
                      isActive ? "bg-brand shadow-[0_0_12px_rgb(var(--brand)/0.8)]" : "bg-transparent")} />
                    <Icon className="h-4 w-4 shrink-0" /> {t(key)}
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
            <button className="lg:hidden" onClick={() => setOpen(true)} aria-label={t("header.openMenu")}><Menu className="h-5 w-5" /></button>
            <nav className="flex min-w-0 items-center gap-1.5 text-sm" aria-label="Breadcrumb">
              <span className="font-semibold text-slate-300">PatchProof</span>
              {crumb && <><span className="text-slate-600">/</span><span className="truncate text-slate-400">{crumb}</span></>}
            </nav>
            <div className="ml-auto flex items-center gap-2">
              <StatusChip ok={dbOk} warn={!dbOk}><Database className="h-3 w-3" /> {health.error ? t("header.offline") : health.data?.database ?? "…"}</StatusChip>
              <StatusChip ok={ollama.data?.model_installed}><Bot className="h-3 w-3" /> {t("header.ai")} {ollama.data?.model_installed ? t("header.aiReady") : t("header.aiOptional")}</StatusChip>
              {USE_MOCKS && showDemo && (
                <Pill className="border-blocked/40 bg-blocked/10 text-blocked ring-0">
                  <span className="h-1.5 w-1.5 rounded-full bg-blocked" /> {t("header.demoData")}
                  <button onClick={() => setShowDemo(false)} aria-label={t("header.dismiss")} className="ml-0.5 text-blocked/70 hover:text-blocked"><X className="h-3 w-3" /></button>
                </Pill>
              )}
              <ThemeToggle />
            </div>
          </header>

          {health.error && (
            <div className="flex flex-wrap items-center gap-3 border-b border-breached/30 bg-breached/10 px-4 py-2.5 text-sm text-rose-200 sm:px-8">
              <WifiOff className="h-4 w-4 shrink-0" />
              <span className="flex-1">{t("header.backendUnreachable")} {health.error.message}</span>
              <button className="rounded-md px-2 py-1 text-rose-100 hover:bg-breached/20" onClick={() => void health.reload()} disabled={health.loading}>
                {health.loading ? t("header.checking") : t("header.retry")}
              </button>
            </div>
          )}
          {health.data?.status === "degraded" && (
            <div className="border-b border-blocked/30 bg-blocked/10 px-4 py-2.5 text-sm text-blocked sm:px-8">
              {t("header.degraded", { db: health.data.database })}
            </div>
          )}

          <main className="mx-auto max-w-[1600px] px-4 py-6 sm:px-8 sm:py-8">
            <Suspense fallback={<Loading />}>
              <Outlet />
            </Suspense>
          </main>
        </div>
      </div>
      <ToastHost />
    </div>
  );
}
