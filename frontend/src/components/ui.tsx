import { AlertTriangle, ArrowUpRight, CheckCircle2, CircleDashed, Loader2, ShieldAlert, XCircle } from "lucide-react";
import { useEffect, useRef, useState, type ButtonHTMLAttributes, type ReactNode } from "react";
import { Link } from "react-router-dom";
import { useT } from "../i18n";
import type { PatchStatus, Severity, Verdict } from "../types/api";

export function cx(...classes: (string | false | null | undefined)[]) {
  return classes.filter(Boolean).join(" ");
}

export function Card({ title, actions, children, className }: {
  title?: ReactNode; actions?: ReactNode; children: ReactNode; className?: string;
}) {
  return (
    <section className={cx("glass glass-hover rise-in rounded-2xl", className)}>
      {(title || actions) && (
        <header className="flex flex-wrap items-center justify-between gap-2 border-b border-line/15 px-5 py-3.5">
          <h2 className="text-sm font-semibold tracking-tightish text-slate-100">{title}</h2>
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
      <div className="min-w-0">
        <h1 className="text-display text-white">{title}</h1>
        {subtitle && <p className="mt-1.5 max-w-3xl text-sm leading-relaxed text-slate-400">{subtitle}</p>}
      </div>
      {actions && <div className="flex flex-wrap gap-2">{actions}</div>}
    </div>
  );
}

type Variant = "primary" | "secondary" | "danger" | "ghost";
export function Button({ variant = "primary", busy, children, className, disabled, ...rest }:
  ButtonHTMLAttributes<HTMLButtonElement> & { variant?: Variant; busy?: boolean }) {
  const styles: Record<Variant, string> = {
    primary: "bg-brand text-brand-ink hover:brightness-110 active:brightness-95 shadow-[0_6px_20px_-8px_rgb(var(--brand)/0.7)]",
    secondary: "border border-line bg-surface-2 text-slate-100 hover:border-slate-600 hover:bg-surface-2/70",
    danger: "bg-breached text-white hover:brightness-110",
    ghost: "text-slate-300 hover:bg-surface-2",
  };
  return (
    <button
      {...rest}
      disabled={disabled || busy}
      className={cx("inline-flex items-center justify-center gap-2 rounded-lg px-3.5 py-2 text-sm font-medium transition-[filter,background,border,transform] duration-150 active:translate-y-px",
        "disabled:cursor-not-allowed disabled:opacity-50 disabled:active:translate-y-0", styles[variant], className)}
    >
      {busy && <Loader2 className="h-4 w-4 animate-spin" />}
      {children}
    </button>
  );
}

const SEVERITY_STYLE: Record<Severity, string> = {
  CRITICAL: "bg-breached/15 text-breached ring-breached/40",
  HIGH: "bg-orange-500/15 text-orange-300 ring-orange-500/40",
  MEDIUM: "bg-blocked/15 text-blocked ring-blocked/40",
  LOW: "bg-brand/15 text-brand ring-brand/40",
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

const VERDICT_MAP = {
  VERIFIED: ["bg-verified/15 text-verified ring-verified/40", CheckCircle2, "VERIFIED"],
  PARTIALLY_VERIFIED: ["bg-blocked/15 text-blocked ring-blocked/40", AlertTriangle, "PARTIALLY VERIFIED"],
  FAILED: ["bg-breached/15 text-breached ring-breached/40", XCircle, "FAILED"],
} as const;

export function VerdictBadge({ verdict, large }: { verdict: Verdict | null; large?: boolean }) {
  if (!verdict) return <Pill className="bg-slate-700/40 text-slate-300 ring-slate-600">NO VERDICT</Pill>;
  const [style, Icon, label] = VERDICT_MAP[verdict];
  return (
    <Pill className={cx(style, large && "px-4 py-1.5 text-sm")}>
      <Icon className={large ? "h-4 w-4" : "h-3.5 w-3.5"} /> {label}
    </Pill>
  );
}

/* ---- Signature motif: the proof stamp. Reused on verdicts, patches, reports. ---- */
type SealKind = "VERIFIED" | "REJECTED" | "BREACHED" | "PARTIAL" | "BLOCKED";
const SEAL_STYLE: Record<SealKind, { ring: string; text: string }> = {
  VERIFIED: { ring: "border-verified/70 text-verified", text: "text-verified" },
  REJECTED: { ring: "border-breached/70 text-breached", text: "text-breached" },
  BREACHED: { ring: "border-breached/70 text-breached", text: "text-breached" },
  PARTIAL: { ring: "border-blocked/70 text-blocked", text: "text-blocked" },
  BLOCKED: { ring: "border-verified/70 text-verified", text: "text-verified" },
};

export function Seal({ kind, sub, size = "md", rotate = -8 }: {
  kind: SealKind; sub?: string; size?: "sm" | "md" | "lg"; rotate?: number;
}) {
  const s = SEAL_STYLE[kind];
  const dims = { sm: "h-16 w-16 text-[10px]", md: "h-24 w-24 text-xs", lg: "h-32 w-32 text-sm" }[size];
  return (
    <div
      className={cx("seal-stamp relative flex flex-col items-center justify-center rounded-full border-2 font-bold uppercase tracking-[0.12em]",
        "bg-[rgb(var(--ink)/0.4)]", s.ring, dims)}
      style={{ ["--seal-rot" as string]: `${rotate}deg` }}
    >
      <span className={cx("absolute rounded-full border opacity-40", s.ring)} style={{ inset: 6 }} />
      <span className={s.text}>{kind}</span>
      {sub && <span className="mt-0.5 text-[0.7em] font-semibold tracking-normal text-slate-400">{sub}</span>}
    </div>
  );
}

export function PatchStatusBadge({ status }: { status: PatchStatus }) {
  const style: Record<PatchStatus, string> = {
    PROPOSED: "bg-slate-700/40 text-slate-200 ring-slate-500",
    APPLIED: "bg-brand/15 text-brand ring-brand/40",
    VERIFIED: "bg-verified/15 text-verified ring-verified/40",
    REJECTED: "bg-breached/15 text-breached ring-breached/40",
    ROLLED_BACK: "bg-slate-700/40 text-slate-400 ring-slate-600",
  };
  return <Pill className={style[status]}>{status.replace("_", " ")}</Pill>;
}

export function TestStatus({ status }: { status: "passed" | "failed" | "error" }) {
  if (status === "passed") return <span className="inline-flex items-center gap-1 text-verified"><CheckCircle2 className="h-4 w-4" />Passed</span>;
  if (status === "failed") return <span className="inline-flex items-center gap-1 text-breached"><XCircle className="h-4 w-4" />Failed</span>;
  return <span className="inline-flex items-center gap-1 text-blocked"><AlertTriangle className="h-4 w-4" />Error</span>;
}

export function Loading({ label }: { label?: string }) {
  const t = useT();
  return (
    <div className="flex items-center gap-2 py-10 text-sm text-slate-400">
      <Loader2 className="h-4 w-4 animate-spin" /> {label ?? t("common.loading")}
    </div>
  );
}

/* ---- Skeleton loaders (used instead of spinners where content has a known shape) ---- */
export function Skeleton({ className }: { className?: string }) {
  return <div className={cx("skeleton rounded-md", className)} />;
}

export function SkeletonStats({ n = 4 }: { n?: number }) {
  return (
    <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
      {Array.from({ length: n }).map((_, i) => (
        <div key={i} className="rounded-xl border border-line bg-surface/70 p-4">
          <Skeleton className="h-3 w-20" />
          <Skeleton className="mt-3 h-8 w-16" />
        </div>
      ))}
    </div>
  );
}

export function SkeletonRows({ rows = 5 }: { rows?: number }) {
  return (
    <div className="space-y-2">
      {Array.from({ length: rows }).map((_, i) => <Skeleton key={i} className="h-11 w-full" />)}
    </div>
  );
}

export function ErrorBox({ error, onRetry }: { error: Error | null; onRetry?: () => void }) {
  if (!error) return null;
  return (
    <div className="flex items-start gap-3 rounded-lg border border-breached/40 bg-breached/10 p-4 text-sm text-rose-200">
      <ShieldAlert className="mt-0.5 h-4 w-4 shrink-0" />
      <div className="flex-1">{error.message}</div>
      {onRetry && <Button variant="ghost" onClick={onRetry}>Retry</Button>}
    </div>
  );
}

export function Empty({ children, icon }: { children: ReactNode; icon?: ReactNode }) {
  return (
    <div className="flex flex-col items-center gap-3 rounded-xl border border-dashed border-line bg-surface-2/30 py-12 text-center text-sm text-slate-400">
      <div className="flex h-11 w-11 items-center justify-center rounded-full border border-line bg-surface-2 text-slate-500">
        {icon ?? <CircleDashed className="h-5 w-5" />}
      </div>
      <div className="max-w-sm">{children}</div>
    </div>
  );
}

/* ---- Count-up + sparkline for stat tiles ---- */
export function useCountUp(target: number, ms = 650) {
  const [n, setN] = useState(0);
  const reduce = usePrefersReducedMotion();
  useEffect(() => {
    if (reduce || target === 0) { setN(target); return; }
    let raf = 0;
    const start = performance.now();
    const tick = (t: number) => {
      const p = Math.min(1, (t - start) / ms);
      setN(Math.round((1 - Math.pow(1 - p, 3)) * target));
      if (p < 1) raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [target, ms, reduce]);
  return n;
}

export function usePrefersReducedMotion() {
  const [reduce, setReduce] = useState(false);
  useEffect(() => {
    const mq = window.matchMedia("(prefers-reduced-motion: reduce)");
    setReduce(mq.matches);
    const on = () => setReduce(mq.matches);
    mq.addEventListener("change", on);
    return () => mq.removeEventListener("change", on);
  }, []);
  return reduce;
}

export function Sparkline({ data, className, stroke = "rgb(var(--brand))" }: { data: number[]; className?: string; stroke?: string }) {
  if (data.length < 2) return null;
  const w = 72, h = 22, max = Math.max(...data), min = Math.min(...data), span = max - min || 1;
  const pts = data.map((d, i) => `${(i / (data.length - 1)) * w},${h - ((d - min) / span) * (h - 3) - 1.5}`).join(" ");
  return (
    <svg viewBox={`0 0 ${w} ${h}`} className={cx("h-5 w-[72px]", className)} fill="none" preserveAspectRatio="none" aria-hidden="true">
      <polyline points={pts} stroke={stroke} strokeWidth="1.5" strokeLinejoin="round" strokeLinecap="round" />
    </svg>
  );
}

export function Stat({ label, value, hint, accent, trend, to, ariaLabel }: {
  label: string; value: ReactNode; hint?: string; accent?: string; trend?: number[];
  to?: string; ariaLabel?: string;
}) {
  const numeric = typeof value === "number" ? value : null;
  const counted = useCountUp(numeric ?? 0);
  const body = (
    <>
      <div className="flex items-start justify-between gap-2">
        <div className="text-[11px] font-semibold uppercase tracking-[0.14em] text-slate-400">{label}</div>
        {to ? <ArrowUpRight className="h-4 w-4 text-slate-600 transition-colors group-hover:text-brand" />
            : trend && trend.length > 1 ? <Sparkline data={trend} className="opacity-70 transition-opacity group-hover:opacity-100" /> : null}
      </div>
      <div className={cx("mt-2.5 text-[2rem] font-semibold leading-none tabular-nums tracking-tightish", accent ?? "text-white")}>
        {numeric !== null ? counted : value}
      </div>
      {to && trend && trend.length > 1 && <div className="mt-2"><Sparkline data={trend} className="opacity-70 transition-opacity group-hover:opacity-100" /></div>}
      {hint && <div className="mt-1.5 text-xs text-slate-500">{hint}</div>}
    </>
  );
  const base = "group glass glass-hover rise-in rounded-2xl p-4";
  if (to) {
    return (
      <Link to={to} aria-label={ariaLabel ?? label} className={cx(base, "block cursor-pointer")}>
        {body}
      </Link>
    );
  }
  return <div className={base}>{body}</div>;
}

/* ---- Toasts ---- */
type Toast = { id: number; text: string; tone: "ok" | "warn" | "err" };
let _toastSink: ((t: Omit<Toast, "id">) => void) | null = null;
export const toast = {
  ok: (text: string) => _toastSink?.({ text, tone: "ok" }),
  warn: (text: string) => _toastSink?.({ text, tone: "warn" }),
  err: (text: string) => _toastSink?.({ text, tone: "err" }),
};

export function ToastHost() {
  const [items, setItems] = useState<Toast[]>([]);
  const idRef = useRef(0);
  useEffect(() => {
    _toastSink = (t) => {
      const id = ++idRef.current;
      setItems((xs) => [...xs, { ...t, id }]);
      setTimeout(() => setItems((xs) => xs.filter((x) => x.id !== id)), 3600);
    };
    return () => { _toastSink = null; };
  }, []);
  const tone = { ok: "border-verified/40 text-verified", warn: "border-blocked/40 text-blocked", err: "border-breached/40 text-rose-200" };
  const Icon = { ok: CheckCircle2, warn: AlertTriangle, err: XCircle };
  return (
    <div className="pointer-events-none fixed bottom-4 right-4 z-50 flex w-80 max-w-[calc(100vw-2rem)] flex-col gap-2">
      {items.map((t) => {
        const I = Icon[t.tone];
        return (
          <div key={t.id} className={cx("toast-in pointer-events-auto flex items-start gap-2 rounded-lg border bg-surface-2 px-3.5 py-2.5 text-sm text-slate-200 shadow-pop", tone[t.tone])}>
            <I className="mt-0.5 h-4 w-4 shrink-0" />
            <span className="flex-1 text-slate-200">{t.text}</span>
          </div>
        );
      })}
    </div>
  );
}

export const fmtDate = (iso: string | null) => (iso ? new Date(iso).toLocaleString() : "—");
export const vulnLabel = (t: string) => (t === "sqli" ? "SQL Injection" : t === "idor" ? "Broken Access Control (IDOR)" : t);
export const strategyLabel = (s: string) =>
  ({ parameterized_query: "Parameterised query", ownership_check: "Server-side ownership check",
     deny_all_demo: "Deny-all (deliberately over-restrictive demo)",
     naive_blocklist_demo: "Naive blocklist (deliberately bypassable demo)" } as Record<string, string>)[s] ?? s;
