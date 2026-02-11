/**
 * Theme Module
 *
 * Centralized theming for TUI components.
 * Re-exports colors, detection, and context hooks.
 */

export { darkColors, lightColors, type ThemeColors, type ColorName } from "./colors";
export { detectColorScheme, type ColorScheme } from "./detect";
export { ThemeProvider, useTheme, useColors } from "./context";

import { darkColors, type ThemeColors } from "./colors";
import type { PermissionTier } from "../../core/operator";

/**
 * Get the appropriate color for a permission tier.
 * Lower tiers (1-2) are green (safe), higher tiers are increasingly risky.
 */
export function getTierColor(tier: PermissionTier, themeColors?: ThemeColors) {
  const c = themeColors ?? darkColors;
  if (tier <= 2) return c.greenAccent;
  if (tier === 3) return c.yellowText;
  if (tier === 4) return c.orangeText;
  return c.redText;
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
