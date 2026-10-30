import {
  AlertTriangle,
  CheckCircle2,
  CircleDashed,
  HelpCircle,
  Loader2,
  ShieldAlert,
  XCircle,
} from "lucide-react";
import type { ButtonHTMLAttributes, ReactNode } from "react";
import type { PatchStatus, Severity, Verdict } from "../types/api";

export function cx(...classes: (string | false | null | undefined)[]) {
  return classes.filter(Boolean).join(" ");
}

/** Clean container card with subtle borders and clear header separation */
export function Card({
  title,
  subtitle,
  actions,
  children,
  className,
}: {
  title?: ReactNode;
  subtitle?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <section className={cx("rounded-xl border border-slate-800/80 bg-[#10141d]/80 shadow-sm backdrop-blur-sm", className)}>
      {(title || actions || subtitle) && (
        <header className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800/80 px-5 py-3.5">
          <div>
            <h2 className="text-sm font-semibold tracking-tight text-slate-200">{title}</h2>
            {subtitle && <p className="mt-0.5 text-xs text-slate-500">{subtitle}</p>}
          </div>
          {actions && <div className="flex items-center gap-2">{actions}</div>}
        </header>
      )}
      <div className="p-5">{children}</div>
    </section>
  );
}

/** Clean, human-readable page header with purposeful hierarchy */
export function PageHeader({
  title,
  subtitle,
  actions,
  badge,
}: {
  title: string;
  subtitle?: ReactNode;
  actions?: ReactNode;
  badge?: ReactNode;
}) {
  return (
    <div className="mb-7 flex flex-wrap items-start justify-between gap-4 border-b border-slate-800/60 pb-5">
      <div>
        <div className="flex items-center gap-2.5">
          <h1 className="text-xl font-semibold tracking-tight text-white sm:text-2xl">{title}</h1>
          {badge}
        </div>
        {subtitle && <p className="mt-1 text-sm text-slate-400">{subtitle}</p>}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </div>
  );
}

type Variant = "primary" | "secondary" | "danger" | "ghost";

/** Tactile, accessible buttons with natural feedback */
export function Button({
  variant = "primary",
  busy,
  children,
  className,
  disabled,
  ...rest
}: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: Variant; busy?: boolean }) {
  const styles: Record<Variant, string> = {
    primary:
      "bg-sky-500 hover:bg-sky-400 text-slate-950 font-semibold shadow-sm hover:shadow active:scale-[0.98] border border-sky-400/40",
    secondary:
      "border border-slate-700/80 bg-slate-800/80 hover:bg-slate-700/80 text-slate-200 font-medium active:scale-[0.98]",
    danger:
      "border border-rose-500/30 bg-rose-500/10 hover:bg-rose-500/20 text-rose-300 font-medium active:scale-[0.98]",
    ghost:
      "text-slate-400 hover:text-slate-200 hover:bg-slate-800/50 font-medium",
  };

  return (
    <button
      {...rest}
      disabled={disabled || busy}
      className={cx(
        "inline-flex items-center justify-center gap-2 rounded-lg px-3.5 py-2 text-xs sm:text-sm transition-all duration-150",
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

/** Subtle status pill inspired by GitHub & Linear tag systems */
export function Pill({ className, children }: { className?: string; children: ReactNode }) {
  return (
    <span
      className={cx(
        "inline-flex items-center gap-1.5 rounded-md px-2.5 py-0.5 text-xs font-medium border",
        className
      )}
    >
      {children}
    </span>
  );
}

const SEVERITY_STYLE: Record<Severity, string> = {
  CRITICAL: "border-rose-500/30 bg-rose-500/10 text-rose-300",
  HIGH: "border-orange-500/30 bg-orange-500/10 text-orange-300",
  MEDIUM: "border-amber-500/30 bg-amber-500/10 text-amber-300",
  LOW: "border-sky-500/30 bg-sky-500/10 text-sky-300",
};

export const SeverityBadge = ({ severity }: { severity: Severity }) => (
  <Pill className={SEVERITY_STYLE[severity]}>
    <span className="h-1.5 w-1.5 rounded-full bg-current opacity-70" />
    {severity}
  </Pill>
);

export function VerdictBadge({ verdict, large }: { verdict: Verdict | null; large?: boolean }) {
  if (!verdict) {
    return (
      <Pill className="border-slate-700 bg-slate-800/60 text-slate-400">
        <HelpCircle className="h-3 w-3" />
        No Verdict
      </Pill>
    );
  }

  const map = {
    VERIFIED: ["border-emerald-500/30 bg-emerald-500/10 text-emerald-300", CheckCircle2, "VERIFIED"],
    PARTIALLY_VERIFIED: ["border-amber-500/30 bg-amber-500/10 text-amber-300", AlertTriangle, "PARTIALLY VERIFIED"],
    FAILED: ["border-rose-500/30 bg-rose-500/10 text-rose-300", XCircle, "FAILED"],
  } as const;

  const [style, Icon, label] = map[verdict];
  return (
    <Pill className={cx(style, large && "px-3.5 py-1 text-sm font-semibold")}>
      <Icon className={large ? "h-4 w-4" : "h-3.5 w-3.5"} /> {label}
    </Pill>
  );
}

export function PatchStatusBadge({ status }: { status: PatchStatus }) {
  const style: Record<PatchStatus, string> = {
    PROPOSED: "border-slate-700 bg-slate-800/80 text-slate-300",
    APPLIED: "border-sky-500/30 bg-sky-500/10 text-sky-300",
    VERIFIED: "border-emerald-500/30 bg-emerald-500/10 text-emerald-300",
    REJECTED: "border-rose-500/30 bg-rose-500/10 text-rose-300",
    ROLLED_BACK: "border-slate-700 bg-slate-800/50 text-slate-400",
  };
  return (
    <Pill className={style[status]}>
      <span className="h-1.5 w-1.5 rounded-full bg-current opacity-70" />
      {status.replace("_", " ")}
    </Pill>
  );
}

export function TestStatus({ status }: { status: "passed" | "failed" | "error" }) {
  if (status === "passed") {
    return (
      <span className="inline-flex items-center gap-1.5 text-xs font-medium text-emerald-400">
        <CheckCircle2 className="h-3.5 w-3.5" />
        Passed
      </span>
    );
  }
  if (status === "failed") {
    return (
      <span className="inline-flex items-center gap-1.5 text-xs font-medium text-rose-400">
        <XCircle className="h-3.5 w-3.5" />
        Failed
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1.5 text-xs font-medium text-amber-400">
      <AlertTriangle className="h-3.5 w-3.5" />
      Error
    </span>
  );
}

export function Loading({ label = "Loading data…" }: { label?: string }) {
  return (
    <div className="flex items-center justify-center gap-2.5 py-12 text-xs sm:text-sm text-slate-400">
      <Loader2 className="h-4 w-4 animate-spin text-sky-400" />
      <span>{label}</span>
    </div>
  );
}

export function ErrorBox({ error, onRetry }: { error: Error | null; onRetry?: () => void }) {
  if (!error) return null;
  return (
    <div className="flex items-start gap-3 rounded-lg border border-rose-500/30 bg-rose-500/8 p-4 text-xs sm:text-sm text-rose-300">
      <ShieldAlert className="mt-0.5 h-4 w-4 shrink-0 text-rose-400" />
      <div className="flex-1 leading-relaxed">{error.message}</div>
      {onRetry && (
        <Button variant="ghost" onClick={onRetry} className="h-7 text-xs">
          Try again
        </Button>
      )}
    </div>
  );
}

export function Empty({ children }: { children: ReactNode }) {
  return (
    <div className="flex flex-col items-center justify-center gap-2.5 py-12 text-center text-xs sm:text-sm text-slate-500">
      <CircleDashed className="h-7 w-7 text-slate-600" />
      <div className="max-w-sm leading-relaxed text-slate-400">{children}</div>
    </div>
  );
}

/** Real telemetry metric card with clean typography */
export function Stat({
  label,
  value,
  hint,
  accent,
}: {
  label: string;
  value: ReactNode;
  hint?: string;
  accent?: string;
}) {
  return (
    <div className="rounded-xl border border-slate-800/80 bg-[#10141d]/80 p-4 transition-all hover:border-slate-700/80">
      <div className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">{label}</div>
      <div className={cx("mt-2 text-2xl font-bold tracking-tight tabular-nums", accent ?? "text-white")}>
        {value}
      </div>
      {hint && <div className="mt-1.5 text-[11px] text-slate-500">{hint}</div>}
    </div>
  );
}

export const fmtDate = (iso: string | null) => (iso ? new Date(iso).toLocaleString() : "—");
export const vulnLabel = (t: string) =>
  t === "sqli" ? "SQL Injection" : t === "idor" ? "Broken Access Control (IDOR)" : t;

export const strategyLabel = (s: string) =>
  ({
    parameterized_query: "Parameterised query",
    ownership_check: "Server-side ownership check",
    deny_all_demo: "Deny-all (deliberately over-restrictive demo)",
  }[s] ?? s);
