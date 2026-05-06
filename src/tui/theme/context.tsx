/**
 * Theme Context
 *
 * React Context-based theme provider. Manages the active theme and dark/light
 * mode, resolving per-token { dark, light } values to flat RGBA colors.
 */

import type { RGBA } from "@opentui/core";
import {
  createContext,
  type ReactNode,
  useCallback,
  useContext,
  useMemo,
  useState,
} from "react";
import { DEFAULT_THEME_NAME, getAllThemeNames, getTheme } from "./registry";
import type {
  ColorMode,
  ThemeColors,
  ThemeColorValue,
  ThemeDefinition,
} from "./types";

interface ThemeContextValue {
  /** Current active theme definition */
  theme: ThemeDefinition;
  /** Resolved colors for the current mode */
  colors: ThemeColors;
  /** Current dark/light mode */
  mode: ColorMode;
  /** All available theme names */
  availableThemes: string[];
  /** Switch to a different theme by name */
  setTheme: (name: string) => void;
  /** Toggle between dark and light mode */
  toggleMode: () => void;
  /** Set a specific mode */
  setMode: (mode: ColorMode) => void;
}

const ThemeContext = createContext<ThemeContextValue | null>(null);

/** Resolve a ThemeColorValue to an RGBA for the given mode */
function resolveColor(value: ThemeColorValue, mode: ColorMode): RGBA {
  if ("r" in value) return value; // Already a plain RGBA
  return value[mode];
}

/** Resolve all theme colors for a given mode */
export function resolveThemeColors(
  theme: ThemeDefinition,
  mode: ColorMode,
): ThemeColors {
  const entries = Object.entries(theme.colors) as [string, ThemeColorValue][];
  const resolved: Record<string, RGBA> = {};
  for (const [key, value] of entries) {
    resolved[key] = resolveColor(value, mode);
  }
  return resolved as unknown as ThemeColors;
}

interface ThemeProviderProps {
  initialTheme?: string;
  initialMode?: ColorMode;
  children: ReactNode;
}

export function ThemeProvider({
  initialTheme,
  initialMode = "dark",
  children,
}: ThemeProviderProps) {
  const [theme, setThemeState] = useState<ThemeDefinition>(() =>
    getTheme(initialTheme ?? DEFAULT_THEME_NAME),
  );
  const [mode, setModeState] = useState<ColorMode>(initialMode);

  const colors = useMemo(() => resolveThemeColors(theme, mode), [theme, mode]);

  const setTheme = useCallback((name: string) => {
    const newTheme = getTheme(name);
    setThemeState(newTheme);
  }, []);

  const toggleMode = useCallback(() => {
    setModeState((prev) => (prev === "dark" ? "light" : "dark"));
  }, []);

  const setMode = useCallback((m: ColorMode) => {
    setModeState(m);
  }, []);

  return (
    <ThemeContext
      value={{
        theme,
        colors,
        mode,
        availableThemes: getAllThemeNames(),
        setTheme,
        toggleMode,
        setMode,
      }}
    >
      {children}
    </ThemeContext>
  );
}

/**
 * Access the current theme's resolved colors and control functions.
 *
 * Usage:
 *   const { colors, setTheme, toggleMode } = useTheme();
 */
export function useTheme() {
  const ctx = useContext(ThemeContext);
  if (!ctx) throw new Error("useTheme() must be used within <ThemeProvider>");
  return ctx;
}
