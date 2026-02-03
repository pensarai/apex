/**
 * Theme Module
 *
 * Centralized theming for TUI components.
 * Re-exports colors and provides helper functions.
 */

export { colors, type ColorName } from "./colors";

import { colors } from "./colors";
import type { PermissionTier } from "../../core/operator";

/**
 * Get the appropriate color for a permission tier.
 * Lower tiers (1-2) are green (safe), higher tiers are increasingly risky.
 */
export function getTierColor(tier: PermissionTier) {
  if (tier <= 2) return colors.greenAccent;
  if (tier === 3) return colors.yellowText;
  if (tier === 4) return colors.orangeText;
  return colors.redText;
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
