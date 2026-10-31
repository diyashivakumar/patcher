// English-only UI. A tiny t(key, vars) helper keeps a single source of strings
// (src/i18n/en.ts) and interpolation, without any language switching.
import { createContext, useCallback, useContext, useMemo, type ReactNode } from "react";
import en, { type TranslationKey } from "./en";

export type Lang = "en";

type Ctx = {
  lang: Lang;
  t: (key: TranslationKey, vars?: Record<string, string | number>) => string;
};

const I18nContext = createContext<Ctx | null>(null);

function translate(key: TranslationKey, vars?: Record<string, string | number>): string {
  let s: string = en[key] ?? (key as string);
  if (vars) for (const [k, v] of Object.entries(vars)) s = s.replace(`{${k}}`, String(v));
  return s;
}

export function I18nProvider({ children }: { children: ReactNode }) {
  const t = useCallback<Ctx["t"]>((key, vars) => translate(key, vars), []);
  const value = useMemo(() => ({ lang: "en" as Lang, t }), [t]);
  return <I18nContext.Provider value={value}>{children}</I18nContext.Provider>;
}

export function useI18n(): Ctx {
  const ctx = useContext(I18nContext);
  if (!ctx) throw new Error("useI18n must be used within <I18nProvider>");
  return ctx;
}

/** Convenience: just the translate function. */
export function useT() {
  return useI18n().t;
}
