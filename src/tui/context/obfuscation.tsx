/**
 * Obfuscation context for the TUI.
 *
 * Activates when the CLI was started with `--obfuscate` (which sets
 * `PENSAR_OBFUSCATE=1`) or when the user toggles it at runtime via the
 * `/obfuscate` slash command. When active, the engine inside
 * `core/obfuscation` is enabled globally so any module that imports
 * `obfuscate()` will redact text consistently across the UI.
 */

import {
  createContext,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";
import {
  resetObfuscation,
  setObfuscationEnabled,
  obfuscate as engineObfuscate,
} from "../../core/obfuscation";

interface ObfuscationContextValue {
  enabled: boolean;
  /** Enable, disable, or toggle obfuscation. Toggle when no value is passed. */
  setEnabled: (enabled?: boolean) => void;
  toggle: () => void;
  redact: (input: string) => string;
}

const ObfuscationContext = createContext<ObfuscationContextValue>({
  enabled: false,
  setEnabled: () => {},
  toggle: () => {},
  redact: (s) => s,
});

interface ObfuscationProviderProps {
  initialEnabled: boolean;
  children: ReactNode;
}

export function ObfuscationProvider({
  initialEnabled,
  children,
}: ObfuscationProviderProps) {
  const [enabled, setEnabledState] = useState<boolean>(initialEnabled);

  // Keep the global engine state in sync with React state. The engine is a
  // module-level singleton because many code paths (markdown rendering,
  // syntax highlighting, footer status text) are not React components and
  // need a synchronous gate without prop drilling.
  useEffect(() => {
    setObfuscationEnabled(enabled);
  }, [enabled]);

  const value = useMemo<ObfuscationContextValue>(() => {
    const setEnabled = (next?: boolean) => {
      setEnabledState((prev) => {
        const target = typeof next === "boolean" ? next : !prev;
        if (target === prev) return prev;
        // Reset placeholder counters when turning obfuscation on so a fresh
        // mapping starts at <CATEGORY_1>. Leave the mapping alone on disable
        // so re-enabling within the same session reuses prior placeholders.
        if (target && !prev) resetObfuscation();
        return target;
      });
    };
    return {
      enabled,
      setEnabled,
      toggle: () => setEnabled(),
      redact: (input: string) => (enabled ? engineObfuscate(input) : input),
    };
  }, [enabled]);

  return (
    <ObfuscationContext.Provider value={value}>
      {children}
    </ObfuscationContext.Provider>
  );
}

export function useObfuscation(): ObfuscationContextValue {
  return useContext(ObfuscationContext);
}
