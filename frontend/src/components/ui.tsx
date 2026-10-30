import { AlertTriangle, CheckCircle2, CircleDashed, Loader2, ShieldAlert, XCircle } from "lucide-react";
import type { ButtonHTMLAttributes, ReactNode } from "react";
import type { PatchStatus, Severity, Verdict } from "../types/api";

export function cx(...classes: (string | false | null | undefined)[]) {
  return classes.filter(Boolean).join(" ");
}

export function Card({ title, actions, children, className }: {
  title?: ReactNode; actions?: ReactNode; children: ReactNode; className?: string;
}) {
  return (
    <section className={cx(
      "rounded-2xl border border-slate-800/60 bg-slate-900/50 shadow-xl shadow-slate-950/50 backdrop-blur-sm transition-all",
      className
    )}>
      {(title || actions) && (
        <header className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800/50 px-5 py-3.5">
          <h2 className="text-sm font-semibold text-slate-100">{title}</h2>
          {actions}
        </header>
      )}
      <div className="p-5">{children}</div>
    </section>
  );
}

export function PageHeader({ title, subtitle, actions }: { title: string; subtitle?: ReactNode; actions?: ReactNode }) {
  return (
    <div className="mb-7 flex flex-wrap items-end justify-between gap-4 animate-fade-in">
      <div>
        <h1 className="text-2xl font-bold tracking-tight text-white">{title}</h1>
        {subtitle && <p className="mt-1.5 text-sm text-slate-400">{subtitle}</p>}
      </div>
      {actions && <div className="flex flex-wrap gap-2">{actions}</div>}
    </div>
  );
}

type Variant = "primary" | "secondary" | "danger" | "ghost";
export function Button({ variant = "primary", busy, children, className, disabled, ...rest }:
  ButtonHTMLAttributes<HTMLButtonElement> & { variant?: Variant; busy?: boolean }) {
  const styles: Record<Variant, string> = {
    primary:
      "bg-gradient-to-r from-sky-500 to-sky-400 text-slate-950 font-semibold shadow-lg shadow-sky-500/20 hover:from-sky-400 hover:to-sky-300 hover:shadow-sky-400/30 active:scale-95",
    secondary:
      "border border-slate-700 bg-slate-800/80 text-slate-100 hover:bg-slate-700/80 hover:border-slate-600 active:scale-95",
    danger:
      "bg-gradient-to-r from-rose-600 to-rose-500 text-white shadow-lg shadow-rose-500/20 hover:from-rose-500 hover:to-rose-400 active:scale-95",
    ghost:
      "text-slate-300 hover:bg-slate-800/60 hover:text-slate-100 active:scale-95",
  };
  return (
    <button
      {...rest}
      disabled={disabled || busy}
      className={cx(
        "inline-flex items-center justify-center gap-2 rounded-xl px-4 py-2 text-sm transition-all duration-150",
        "disabled:cursor-not-allowed disabled:opacity-40",
        styles[variant],
        className
      )}
    >
      {busy && <Loader2 className="h-3.5 w-3.5 animate-spin" />}
      {children}
    </button>
  );
}

const SEVERITY_STYLE: Record<Severity, string> = {
  CRITICAL: "bg-rose-500/15 text-rose-300 ring-rose-500/40 shadow-rose-500/10 shadow-sm",
  HIGH: "bg-orange-500/15 text-orange-300 ring-orange-500/40 shadow-orange-500/10 shadow-sm",
  MEDIUM: "bg-amber-500/15 text-amber-300 ring-amber-500/40",
  LOW: "bg-sky-500/15 text-sky-300 ring-sky-500/40",
};

export function Pill({ className, children }: { className: string; children: ReactNode }) {
  return (
    <span className={cx("inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-xs font-semibold ring-1 ring-inset", className)}>
      {children}
    </span>
  );
}

export const SeverityBadge = ({ severity }: { severity: Severity }) => (
  <Pill className={SEVERITY_STYLE[severity]}>{severity}</Pill>
);

export function VerdictBadge({ verdict, large }: { verdict: Verdict | null; large?: boolean }) {
  if (!verdict) return <Pill className="bg-slate-700/40 text-slate-300 ring-slate-600">NO VERDICT</Pill>;
  const map = {
    VERIFIED: ["bg-emerald-500/15 text-emerald-300 ring-emerald-500/40 shadow-emerald-500/10 shadow-sm", CheckCircle2, "VERIFIED"],
    PARTIALLY_VERIFIED: ["bg-amber-500/15 text-amber-300 ring-amber-500/40", AlertTriangle, "PARTIALLY VERIFIED"],
    FAILED: ["bg-rose-500/15 text-rose-300 ring-rose-500/40 shadow-rose-500/10 shadow-sm", XCircle, "FAILED"],
  } as const;
  const [style, Icon, label] = map[verdict];
  return (
    <Pill className={cx(style, large && "px-4 py-1.5 text-sm")}>
      <Icon className={large ? "h-4 w-4" : "h-3.5 w-3.5"} /> {label}
    </Pill>
  );
}

export function PatchStatusBadge({ status }: { status: PatchStatus }) {
  const style: Record<PatchStatus, string> = {
    PROPOSED: "bg-slate-700/40 text-slate-200 ring-slate-500",
    APPLIED: "bg-sky-500/15 text-sky-300 ring-sky-500/40",
    VERIFIED: "bg-emerald-500/15 text-emerald-300 ring-emerald-500/40",
    REJECTED: "bg-rose-500/15 text-rose-300 ring-rose-500/40",
    ROLLED_BACK: "bg-slate-700/40 text-slate-400 ring-slate-600",
  };
  return <Pill className={style[status]}>{status.replace("_", " ")}</Pill>;
}

export function TestStatus({ status }: { status: "passed" | "failed" | "error" }) {
  if (status === "passed")
    return (
      <span className="inline-flex items-center gap-1.5 rounded-full bg-emerald-500/10 px-2.5 py-0.5 text-xs font-semibold text-emerald-400 ring-1 ring-inset ring-emerald-500/30">
        <CheckCircle2 className="h-3.5 w-3.5" /> Passed
      </span>
    );
  if (status === "failed")
    return (
      <span className="inline-flex items-center gap-1.5 rounded-full bg-rose-500/10 px-2.5 py-0.5 text-xs font-semibold text-rose-400 ring-1 ring-inset ring-rose-500/30">
        <XCircle className="h-3.5 w-3.5" /> Failed
      </span>
    );
  return (
    <span className="inline-flex items-center gap-1.5 rounded-full bg-amber-500/10 px-2.5 py-0.5 text-xs font-semibold text-amber-400 ring-1 ring-inset ring-amber-500/30">
      <AlertTriangle className="h-3.5 w-3.5" /> Error
    </span>
  );
}

export function Loading({ label = "Loading…" }: { label?: string }) {
  return (
    <div className="flex flex-col items-center gap-4 py-14">
      <div className="relative h-10 w-10">
        <div className="absolute inset-0 rounded-full border-2 border-slate-800" />
        <div className="absolute inset-0 rounded-full border-2 border-t-sky-500 animate-spin" />
      </div>
      <p className="text-sm text-slate-400">{label}</p>
    </div>
  );
}

export function ErrorBox({ error, onRetry }: { error: Error | null; onRetry?: () => void }) {
  if (!error) return null;
  return (
    <div className="flex items-start gap-3 rounded-xl border border-rose-500/30 bg-rose-500/8 px-4 py-3.5 text-sm text-rose-200">
      <ShieldAlert className="mt-0.5 h-4 w-4 shrink-0 text-rose-400" />
      <div className="flex-1 leading-relaxed">{error.message}</div>
      {onRetry && (
        <Button variant="ghost" onClick={onRetry} className="text-rose-300 hover:bg-rose-500/10">
          Retry
        </Button>
      )}
    </div>
  );
}

export function Empty({ children }: { children: ReactNode }) {
  return (
    <div className="flex flex-col items-center gap-3 py-14 text-center">
      <div className="flex h-12 w-12 items-center justify-center rounded-2xl border border-slate-800 bg-slate-900">
        <CircleDashed className="h-6 w-6 text-slate-600" />
      </div>
      <div className="text-sm text-slate-400">{children}</div>
    </div>
  );
}

export function Stat({ label, value, hint, accent }: { label: string; value: ReactNode; hint?: string; accent?: string }) {
  return (
    <div className="group relative overflow-hidden rounded-2xl border border-slate-800/60 bg-slate-900/50 p-5 transition-all duration-200 hover:border-slate-700 hover:shadow-lg hover:shadow-slate-950/60">
      {/* Subtle gradient overlay on hover */}
      <div className="absolute inset-0 bg-gradient-to-br from-sky-500/0 to-indigo-500/0 opacity-0 transition-opacity duration-300 group-hover:from-sky-500/[0.03] group-hover:to-indigo-500/[0.03] group-hover:opacity-100" />
      <div className="relative">
        <div className="text-[11px] font-semibold uppercase tracking-widest text-slate-500">{label}</div>
        <div className={cx("mt-3 text-3xl font-bold tabular-nums tracking-tight animate-count-up", accent ?? "text-white")}>
          {value}
        </div>
        {hint && <div className="mt-1.5 text-xs text-slate-500">{hint}</div>}
      </div>
    </div>
  );
}

export const fmtDate = (iso: string | null) => (iso ? new Date(iso).toLocaleString() : "—");
export const vulnLabel = (t: string) => (t === "sqli" ? "SQL Injection" : t === "idor" ? "Broken Access Control (IDOR)" : t);
export const strategyLabel = (s: string) =>
  ({ parameterized_query: "Parameterised query", ownership_check: "Server-side ownership check",
     deny_all_demo: "Deny-all (deliberately over-restrictive demo)" } as Record<string, string>)[s] ?? s;
