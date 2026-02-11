/**
 * Terminal Color Scheme Detection
 *
 * Detects whether the terminal has a light or dark background.
 * Called once at startup before React mounts.
 */

import { execSync } from "child_process";

export type ColorScheme = "dark" | "light";

/**
 * Detect terminal color scheme synchronously.
 *
 * Detection order:
 * 1. COLORFGBG env var (set by most terminal emulators) — bg >= 7 means light
 * 2. macOS AppleInterfaceStyle — absent means light mode
 * 3. Default to "dark"
 */
export function detectColorScheme(): ColorScheme {
  // 1. Check COLORFGBG env var ("fg;bg" format)
  const colorFgBg = process.env.COLORFGBG;
  if (colorFgBg) {
    const parts = colorFgBg.split(";");
    const bg = parseInt(parts[parts.length - 1], 10);
    if (!isNaN(bg)) {
      return bg >= 7 ? "light" : "dark";
    }
  }

  // 2. macOS: check system appearance
  if (process.platform === "darwin") {
    try {
      execSync("defaults read -g AppleInterfaceStyle", {
        stdio: ["pipe", "pipe", "pipe"],
      });
      // If command succeeds, AppleInterfaceStyle is set → dark mode
      return "dark";
    } catch {
      // Command fails when AppleInterfaceStyle is absent → light mode
      return "light";
    }
  }

  // 3. Default to dark
  return "dark";
}
