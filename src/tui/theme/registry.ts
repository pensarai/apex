/**
 * Theme Registry
 *
 * Stores and retrieves theme definitions by name.
 * Both built-in and custom themes are registered here.
 */

import { writeErrorLog } from "../../core/logger";
import type { ThemeDefinition } from "./types";

const themes = new Map<string, ThemeDefinition>();

export const DEFAULT_THEME_NAME = "apex";

export function registerTheme(theme: ThemeDefinition): void {
  themes.set(theme.name, theme);
}

export function getTheme(name: string): ThemeDefinition {
  const theme = themes.get(name);
  if (!theme) {
    writeErrorLog(
      `Theme "${name}" not found, falling back to default`,
      "THEME",
    );
    return themes.get(DEFAULT_THEME_NAME)!;
  }
  return theme;
}

export function getAllThemeNames(): string[] {
  return Array.from(themes.keys()).sort();
}
