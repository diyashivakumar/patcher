// Shared backend-status context. health + ollama were previously fetched separately
// by both AppLayout and Dashboard (duplicate requests on every dashboard visit).
// Fetching them once here and sharing the result removes those duplicate calls.
import { createContext, useContext, type ReactNode } from "react";
import { useApi } from "./hooks/useApi";
import { api } from "./services/api";
import type { Health, OllamaStatus } from "./types/api";

type Query<T> = { data: T | null; error: Error | null; loading: boolean; reload: () => Promise<void> };
type Ctx = { health: Query<Health>; ollama: Query<OllamaStatus> };

const StatusContext = createContext<Ctx | null>(null);

export function StatusProvider({ children }: { children: ReactNode }) {
  const health = useApi(() => api.health());
  const ollama = useApi(() => api.ollamaStatus());
  return <StatusContext.Provider value={{ health, ollama }}>{children}</StatusContext.Provider>;
}

export function useStatus(): Ctx {
  const ctx = useContext(StatusContext);
  if (!ctx) throw new Error("useStatus must be used within <StatusProvider>");
  return ctx;
}
