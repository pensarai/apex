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
import { colors as legacyColors } from "./colors";
import type { PermissionTier } from "../../core/operator";
import type { RGBA } from "@opentui/core";

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
 * Shows K for thousands, M for millions.
 */
export function formatTokenCount(count: number): string {
  if (count >= 1000000) {
    return `${(count / 1000000).toFixed(1)}M`;
  } else if (count >= 1000) {
    return `${(count / 1000).toFixed(1)}K`;
  }
  return count.toString();
}
