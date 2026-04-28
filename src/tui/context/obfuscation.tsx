/**
 * Obfuscation context for the TUI.
 *
 * Activates when the CLI was started with `--obfuscate` (which sets
 * `PENSAR_OBFUSCATE=1`) or when the user toggles it at runtime via the
 * `/obfuscate` slash command. When active, the engine inside
 * `core/obfuscation` is enabled globally; the actual redaction at
 * render time is handled by the central `TextNodeRenderable` patch in
 * `src/tui/obfuscation/patch.ts`, which intercepts every JSX `<text>`
 * leaf the @opentui/react reconciler creates or updates. Components
 * therefore don't need to call `obfuscate()` on their own strings.
 *
 * On toggle this provider walks the renderer's tree and re-emits each
 * text node from its stored original so already-rendered prose
 * retroactively reflects the new state.
 */

import {
  createContext,
  useContext,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from "react";
import { useRenderer } from "@opentui/react";
import {
  resetObfuscation,
  setObfuscationEnabled,
  isObfuscationEnabled,
  obfuscate as engineObfuscate,
} from "../../core/obfuscation";
import { refreshObfuscatedText } from "../obfuscation/patch";

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
  const renderer = useRenderer();

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
      // mapping starts at [CATEGORY_1]. Leave the mapping alone on disable
      // so re-enabling within the same session reuses prior placeholders
      // and `deobfuscate()` can still expand them back to originals.
      if (target && !current) resetObfuscation();
      // Update the engine FIRST, synchronously, so any render kicked off
      // by the state setter below already sees the new state.
      setObfuscationEnabled(target);
      setEnabledState(target);
      // Walk the renderable tree and re-emit every text node from its
      // stored original. Without this, React's reconciler would skip
      // `commitTextUpdate` on existing text whose string value hasn't
      // changed, so already-rendered prose would lag behind the toggle.
      if (renderer) refreshObfuscatedText(renderer);
    };
    return {
      enabled,
      setEnabled,
      toggle: () => setEnabled(),
      redact: (input: string) => (enabled ? engineObfuscate(input) : input),
    };
  }, [enabled, renderer]);

  return (
    <ObfuscationContext.Provider value={value}>
      {children}
    </ObfuscationContext.Provider>
  );
}

export function useObfuscation(): ObfuscationContextValue {
  return useContext(ObfuscationContext);
}
