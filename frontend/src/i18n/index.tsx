// Lightweight i18n — no external dependency. A context holds the current language;
// t(key, vars) looks it up in the active language, falls back to English, then to the
// key itself. Language persists in localStorage and is reflected on <html lang>.
import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import en, { type TranslationKey } from "./en";
import hi from "./hi";
import kn from "./kn";

export type Lang = "en" | "hi" | "kn";
export const LANGS: { code: Lang; label: string; english: string }[] = [
  { code: "en", label: "English", english: "English" },
  { code: "hi", label: "हिन्दी", english: "Hindi" },
  { code: "kn", label: "ಕನ್ನಡ", english: "Kannada" },
];

const DICTS: Record<Lang, Record<string, string>> = { en, hi, kn };
const STORAGE_KEY = "pp.lang";

function readLang(): Lang {
  try {
    const v = localStorage.getItem(STORAGE_KEY);
    if (v === "en" || v === "hi" || v === "kn") return v;
  } catch {
    /* storage may be unavailable (private mode) */
  }
  return "en";
}

type Ctx = {
  lang: Lang;
  setLang: (l: Lang) => void;
  t: (key: TranslationKey, vars?: Record<string, string | number>) => string;
};

const I18nContext = createContext<Ctx | null>(null);

export function I18nProvider({ children }: { children: ReactNode }) {
  const [lang, setLangState] = useState<Lang>(readLang);

  useEffect(() => {
    document.documentElement.lang = lang;
  }, [lang]);

  const setLang = useCallback((l: Lang) => {
    setLangState(l);
    try {
      localStorage.setItem(STORAGE_KEY, l);
    } catch {
      /* ignore */
    }
  }, []);

  const t = useCallback<Ctx["t"]>(
    (key, vars) => {
      let s = DICTS[lang][key] ?? en[key] ?? (key as string);
      if (vars) for (const [k, v] of Object.entries(vars)) s = s.replace(`{${k}}`, String(v));
      return s;
    },
    [lang],
  );

  const value = useMemo(() => ({ lang, setLang, t }), [lang, setLang, t]);
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
