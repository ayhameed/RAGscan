"use client";

import { useEffect, useState } from "react";

const LLM_PROVIDER_KEY = "ragscan_last_llm_provider";

function labelFor(provider: string): string {
  const val = provider.toLowerCase();
  if (val.includes("fallback")) {
    const parts = provider.split(":");
    if (parts.length > 1 && parts[1].trim()) {
      return `Fallback: ${parts[1].trim()}`;
    }
    return "Fallback: Open Model";
  }
  if (val.includes("anthropic")) return "Primary: Anthropic";
  if (val) return `Provider: ${provider}`;
  return "Provider: awaiting first LLM response";
}

function classFor(provider: string): string {
  const val = provider.toLowerCase();
  if (val.includes("fallback")) return "border-amber-300 bg-amber-50 text-amber-800";
  if (val.includes("anthropic")) return "border-emerald-300 bg-emerald-50 text-emerald-800";
  return "border-slate-300 bg-slate-50 text-slate-700";
}

export default function LlmProviderStatus() {
  const [provider, setProvider] = useState(() => {
    if (typeof window === "undefined") return "";
    return localStorage.getItem(LLM_PROVIDER_KEY) || "";
  });

  useEffect(() => {
    const handler = (event: Event) => {
      const detail = (event as CustomEvent).detail as { provider?: string };
      setProvider((detail?.provider || "").trim());
    };

    window.addEventListener("ragscan-llm-provider", handler as EventListener);
    return () => window.removeEventListener("ragscan-llm-provider", handler as EventListener);
  }, []);

  return (
    <div className={`inline-flex items-center rounded-full border px-3 py-1 text-xs font-medium ${classFor(provider)}`}>
      {labelFor(provider)}
    </div>
  );
}
