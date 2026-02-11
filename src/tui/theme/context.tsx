/**
 * Theme Context
 *
 * Provides theme colors to all TUI components via React context.
 * Follows the same pattern as src/tui/context/config.tsx.
 */

import { createContext, useContext, useMemo, type ReactNode } from "react";
import { darkColors, lightColors, type ThemeColors } from "./colors";
import type { ColorScheme } from "./detect";

type ThemeContext = {
  scheme: ColorScheme;
  colors: ThemeColors;
};

const ctx = createContext<ThemeContext | null>(null);

type ThemeProviderProps = {
  children: ReactNode;
  scheme: ColorScheme;
};

export function ThemeProvider({ children, scheme }: ThemeProviderProps) {
  const value = useMemo(
    () => ({
      scheme,
      colors: scheme === "light" ? lightColors : darkColors,
    }),
    [scheme]
  );

  return <ctx.Provider value={value}>{children}</ctx.Provider>;
}

export function useTheme(): ThemeContext {
  const theme = useContext(ctx);
  if (!theme) {
    throw new Error("useTheme must be called within a ThemeProvider");
  }
  return theme;
}

export function useColors(): ThemeColors {
  return useTheme().colors;
}
