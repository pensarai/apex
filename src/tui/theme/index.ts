/**
 * Theme Module
 *
 * Centralized theming for TUI components.
 * Re-exports the theme system API and legacy colors for backwards compatibility.
 */

// ── Legacy exports (kept during migration) ──────────────────
export { type ColorName, colors } from "./colors";
export { resolveThemeColors, ThemeProvider, useTheme } from "./context";
export { detectTerminalMode } from "./detect-mode";
export {
  DEFAULT_THEME_NAME,
  getAllThemeNames,
  getTheme,
  registerTheme,
} from "./registry";

// ── Built-in themes + terminal mode detection ───────────────
export { registerBuiltinThemes } from "./themes";
// ── New theme system API ────────────────────────────────────
export type {
  ColorMode,
  ThemeColors,
  ThemeColorsInput,
  ThemeColorValue,
  ThemeDefinition,
} from "./types";

import type { RGBA } from "@opentui/core";
import type { PermissionTier } from "../../core/operator";
import { colors as legacyColors } from "./colors";
// ── Helpers ─────────────────────────────────────────────────
import type { ThemeColors } from "./types";

/**
 * Get the appropriate color for a permission tier.
 *
 * Overloaded for backwards compatibility:
 *   getTierColor(tier)          — legacy, uses hardcoded colors
 *   getTierColor(colors, tier)  — theme-aware, uses resolved ThemeColors
 */
export function getTierColor(tier: PermissionTier): RGBA;
export function getTierColor(colors: ThemeColors, tier: PermissionTier): RGBA;
export function getTierColor(
  colorsOrTier: ThemeColors | PermissionTier,
  maybeTier?: PermissionTier,
): RGBA {
  if (typeof colorsOrTier === "number") {
    // Legacy signature: getTierColor(tier)
    const tier = colorsOrTier;
    if (tier <= 2) return legacyColors.greenAccent;
    if (tier === 3) return legacyColors.yellowText;
    if (tier === 4) return legacyColors.orangeText;
    return legacyColors.redText;
  }
  // New signature: getTierColor(colors, tier)
  const colors = colorsOrTier;
  const tier = maybeTier!;
  if (tier <= 2) return colors.tierSafe;
  if (tier === 3) return colors.tierModerate;
  if (tier === 4) return colors.tierRisky;
  return colors.tierDangerous;
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
