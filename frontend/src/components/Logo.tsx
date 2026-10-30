/** PatchProof mark: a geometric shield whose lower half is cut by a proof-tick / stamp notch. */
export function LogoMark({ size = 28, className }: { size?: number; className?: string }) {
  return (
    <svg width={size} height={size} viewBox="0 0 32 32" fill="none" className={className} aria-hidden="true">
      {/* shield */}
      <path
        d="M16 2.5 L27 6.2 V15 C27 22.4 22.2 27.2 16 29.5 C9.8 27.2 5 22.4 5 15 V6.2 Z"
        fill="rgb(var(--brand) / 0.12)"
        stroke="rgb(var(--brand))"
        strokeWidth="1.6"
        strokeLinejoin="round"
      />
      {/* proof tick, drawn as a bold geometric check */}
      <path
        d="M10.5 15.8 L14.4 19.7 L22 11.2"
        stroke="rgb(var(--brand))"
        strokeWidth="2.6"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
      {/* stamp notch -- a small corner cut that reads as 'sealed' */}
      <circle cx="16" cy="15.6" r="9.2" stroke="rgb(var(--brand) / 0.35)" strokeWidth="1" strokeDasharray="2 3" />
    </svg>
  );
}

export function Wordmark({ compact }: { compact?: boolean }) {
  return (
    <div className="leading-tight">
      <div className="font-semibold tracking-tightish text-white">
        Patch<span className="text-brand">Proof</span>
      </div>
      {!compact && <div className="text-[10.5px] uppercase tracking-[0.14em] text-slate-500">Find the Flaw · Prove the Fix</div>}
    </div>
  );
}
