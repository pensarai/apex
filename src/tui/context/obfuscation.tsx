/**
 * Obfuscation context for the TUI.
 *
 * Activates when the CLI was started with `--obfuscate` (which sets
 * `PENSAR_OBFUSCATE=1`). When active, the engine inside
 * `core/obfuscation` is enabled globally so any module that imports
 * `obfuscate()` will redact text consistently across the UI.
 */

import { createContext, useContext, useMemo, type ReactNode } from "react";
import {
  isObfuscationEnabled,
  setObfuscationEnabled,
  obfuscate as engineObfuscate,
} from "../../core/obfuscation";

interface ObfuscationContextValue {
  enabled: boolean;
  redact: (input: string) => string;
}

const ObfuscationContext = createContext<ObfuscationContextValue>({
  enabled: false,
  redact: (s) => s,
});

interface ObfuscationProviderProps {
  enabled: boolean;
  children: ReactNode;
}

export function ObfuscationProvider({
  enabled,
  children,
}: ObfuscationProviderProps) {
  // Enabling is a global side-effect on the engine because many code paths
  // (markdown rendering, syntax highlighting, footer status text) are not
  // React components and need a synchronous gate without prop drilling.
  if (isObfuscationEnabled() !== enabled) {
    setObfuscationEnabled(enabled);
  }

  const value = useMemo<ObfuscationContextValue>(
    () => ({
      enabled,
      redact: (input: string) => (enabled ? engineObfuscate(input) : input),
    }),
    [enabled],
  );

  return (
    <ObfuscationContext.Provider value={value}>
      {children}
    </ObfuscationContext.Provider>
  );
}

export function useObfuscation(): ObfuscationContextValue {
  return useContext(ObfuscationContext);
}
