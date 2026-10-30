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
    <section className={cx("rounded-xl border border-slate-800 bg-slate-900/60", className)}>
      {(title || actions) && (
        <header className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800 px-5 py-3">
          <h2 className="text-sm font-semibold text-slate-200">{title}</h2>
          {actions}
        </header>
      )}
      <div className="p-5">{children}</div>
    </section>
  );
}

export function PageHeader({ title, subtitle, actions }: { title: string; subtitle?: ReactNode; actions?: ReactNode }) {
  return (
    <div className="mb-6 flex flex-wrap items-end justify-between gap-4">
      <div>
        <h1 className="text-2xl font-semibold text-white">{title}</h1>
        {subtitle && <p className="mt-1 text-sm text-slate-400">{subtitle}</p>}
      </div>
      {actions && <div className="flex flex-wrap gap-2">{actions}</div>}
    </div>
  );
}

type Variant = "primary" | "secondary" | "danger" | "ghost";
export function Button({ variant = "primary", busy, children, className, disabled, ...rest }:
  ButtonHTMLAttributes<HTMLButtonElement> & { variant?: Variant; busy?: boolean }) {
  const styles: Record<Variant, string> = {
    primary: "bg-sky-500 text-slate-950 hover:bg-sky-400",
    secondary: "border border-slate-700 bg-slate-800 text-slate-100 hover:bg-slate-700",
    danger: "bg-rose-500 text-white hover:bg-rose-400",
    ghost: "text-slate-300 hover:bg-slate-800",
  };
  return (
    <button
      {...rest}
      disabled={disabled || busy}
      className={cx("inline-flex items-center justify-center gap-2 rounded-lg px-3.5 py-2 text-sm font-medium transition",
        "disabled:cursor-not-allowed disabled:opacity-50", styles[variant], className)}
    >
      {busy && <Loader2 className="h-4 w-4 animate-spin" />}
      {children}
    </button>
  );
}

const SEVERITY_STYLE: Record<Severity, string> = {
  CRITICAL: "bg-rose-500/15 text-rose-300 ring-rose-500/40",
  HIGH: "bg-orange-500/15 text-orange-300 ring-orange-500/40",
  MEDIUM: "bg-amber-500/15 text-amber-300 ring-amber-500/40",
  LOW: "bg-sky-500/15 text-sky-300 ring-sky-500/40",
};

export function Pill({ className, children }: { className: string; children: ReactNode }) {
  return (
    <span className={cx("inline-flex items-center gap-1 rounded-full px-2.5 py-0.5 text-xs font-semibold ring-1 ring-inset", className)}>
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
    VERIFIED: ["bg-emerald-500/15 text-emerald-300 ring-emerald-500/40", CheckCircle2, "VERIFIED"],
    PARTIALLY_VERIFIED: ["bg-amber-500/15 text-amber-300 ring-amber-500/40", AlertTriangle, "PARTIALLY VERIFIED"],
    FAILED: ["bg-rose-500/15 text-rose-300 ring-rose-500/40", XCircle, "FAILED"],
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
  if (status === "passed") return <span className="inline-flex items-center gap-1 text-emerald-400"><CheckCircle2 className="h-4 w-4" />Passed</span>;
  if (status === "failed") return <span className="inline-flex items-center gap-1 text-rose-400"><XCircle className="h-4 w-4" />Failed</span>;
  return <span className="inline-flex items-center gap-1 text-amber-400"><AlertTriangle className="h-4 w-4" />Error</span>;
}

export function Loading({ label = "Loading…" }: { label?: string }) {
  return (
    <div className="flex items-center gap-2 py-10 text-sm text-slate-400">
      <Loader2 className="h-4 w-4 animate-spin" /> {label}
    </div>
  );
}

export function ErrorBox({ error, onRetry }: { error: Error | null; onRetry?: () => void }) {
  if (!error) return null;
  return (
    <div className="flex items-start gap-3 rounded-lg border border-rose-500/40 bg-rose-500/10 p-4 text-sm text-rose-200">
      <ShieldAlert className="mt-0.5 h-4 w-4 shrink-0" />
      <div className="flex-1">{error.message}</div>
      {onRetry && <Button variant="ghost" onClick={onRetry}>Retry</Button>}
    </div>
  );
}

export function Empty({ children }: { children: ReactNode }) {
  return (
    <div className="flex flex-col items-center gap-2 py-10 text-center text-sm text-slate-400">
      <CircleDashed className="h-6 w-6 text-slate-600" />
      {children}
    </div>
  );
}

export function Stat({ label, value, hint, accent }: { label: string; value: ReactNode; hint?: string; accent?: string }) {
  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4">
      <div className="text-xs font-medium uppercase tracking-wide text-slate-400">{label}</div>
      <div className={cx("mt-2 text-3xl font-semibold tabular-nums", accent ?? "text-white")}>{value}</div>
      {hint && <div className="mt-1 text-xs text-slate-500">{hint}</div>}
    </div>
  );
}

export const fmtDate = (iso: string | null) => (iso ? new Date(iso).toLocaleString() : "—");
export const vulnLabel = (t: string) => (t === "sqli" ? "SQL Injection" : t === "idor" ? "Broken Access Control (IDOR)" : t);
export const strategyLabel = (s: string) =>
  ({ parameterized_query: "Parameterised query", ownership_check: "Server-side ownership check",
     deny_all_demo: "Deny-all (deliberately over-restrictive demo)" } as Record<string, string>)[s] ?? s;
