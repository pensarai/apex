/**
 * Centralized Color Theme
 *
 * Single source of truth for all color constants in the TUI.
 * Eliminates 20+ duplicate RGBA declarations across components.
 */

import { RGBA } from "@opentui/core";

export const colors = {
  // Primary accent colors
  greenAccent: RGBA.fromInts(76, 175, 80, 255),
  cyanAccent: RGBA.fromInts(0, 188, 212, 255),

  // Text colors
  creamText: RGBA.fromInts(255, 248, 220, 255),
  dimText: RGBA.fromInts(120, 120, 120, 255),

  // Semantic colors
  toolColor: RGBA.fromInts(100, 180, 255, 255),
  errorColor: RGBA.fromInts(244, 67, 54, 255),
  successColor: RGBA.fromInts(100, 200, 100, 255),

  // Warning/status colors
  yellowText: RGBA.fromInts(255, 235, 59, 255),
  orangeText: RGBA.fromInts(255, 152, 0, 255),
  redText: RGBA.fromInts(244, 67, 54, 255),

  // Code/syntax highlighting
  codeColor: RGBA.fromInts(100, 255, 100, 255),
  linkColor: RGBA.fromInts(100, 200, 255, 255),

  // UI element colors
  borderDark: RGBA.fromInts(30, 30, 30, 255),
  backgroundDark: RGBA.fromInts(40, 40, 40, 255),
  backgroundDarker: RGBA.fromInts(10, 10, 10, 255),
} as const;

export type ColorName = keyof typeof colors;
