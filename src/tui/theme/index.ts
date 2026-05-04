/**
 * Theme Module
 *
 * Centralized theming for TUI components.
 * Re-exports the theme system API and legacy colors for backwards compatibility.
 */

// ── New theme system API ────────────────────────────────────
export type {
  ThemeColors,
  ThemeColorValue,
  ThemeColorsInput,
  ThemeDefinition,
  ColorMode,
} from "./types";
export {
  registerTheme,
  getTheme,
  getAllThemeNames,
  DEFAULT_THEME_NAME,
} from "./registry";
export { ThemeProvider, useTheme, resolveThemeColors } from "./context";

// ── Legacy exports (kept during migration) ──────────────────
export { colors, type ColorName } from "./colors";

// ── Helpers ─────────────────────────────────────────────────
import type { ThemeColors } from "./types";
import type { CommandIntent } from "../../core/operator";
import type { RGBA } from "@opentui/core";

/**
 * Get the display color for a command intent.
 *
 * Binary: safe → muted green token (`tierSafe`), destructive → red
 * warning token (`tierDangerous`). The underlying theme tokens keep
 * their names so existing dark/light palettes continue to work.
 */
export function getIntentColor(
  colors: ThemeColors,
  intent: CommandIntent,
): RGBA {
  return intent === "safe" ? colors.tierSafe : colors.tierDangerous;
}

/**
 * Format token count for display.
 * Shows K for thousands, M for millions. Whole-number K/M values
 * render without a trailing `.0` (e.g. `200K`, `1M`); fractional
 * values keep one decimal (`1.2K`, `1.5M`).
 */
export function formatTokenCount(count: number): string {
  if (count >= 1_000_000) {
    const v = count / 1_000_000;
    return `${Number.isInteger(v) ? v.toFixed(0) : v.toFixed(1)}M`;
  }
  if (count >= 1000) {
    const v = count / 1000;
    return `${Number.isInteger(v) ? v.toFixed(0) : v.toFixed(1)}K`;
  }
  return count.toString();
}
