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
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from "react";
import {
  resetObfuscation,
  setObfuscationEnabled,
  isObfuscationEnabled,
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
  // Initialise the engine ONCE on first mount, before any consumer
  // renders, so the first frame sees the right state. Critically this
  // must NOT run on every render — otherwise the next render after a
  // toggle would overwrite the just-flipped engine state with the
  // (forever-`false`) `initialEnabled` prop and the toggle would be
  // silently undone.
  const initializedRef = useRef(false);
  if (!initializedRef.current) {
    initializedRef.current = true;
    setObfuscationEnabled(initialEnabled);
  }
  const [enabled, setEnabledState] = useState<boolean>(initialEnabled);

  const value = useMemo<ObfuscationContextValue>(() => {
    const setEnabled = (next?: boolean) => {
      // Read live engine state rather than the captured `enabled` from
      // closure. This makes the function safe against stale references
      // — a caller that grabbed `setEnabled` on an early render still
      // toggles correctly after subsequent flips.
      const current = isObfuscationEnabled();
      const target = typeof next === "boolean" ? next : !current;
      if (target === current) return;
      // Reset placeholder counters when turning obfuscation on so a fresh
      // mapping starts at <CATEGORY_1>. Leave the mapping alone on disable
      // so re-enabling within the same session reuses prior placeholders
      // and `deobfuscate()` can still expand them back to originals.
      if (target && !current) resetObfuscation();
      // Update the engine FIRST, synchronously, so any render kicked off
      // by the state setter below already sees the new state.
      setObfuscationEnabled(target);
      setEnabledState(target);
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
