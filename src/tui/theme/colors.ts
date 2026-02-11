/**
 * Centralized Color Theme
 *
 * Single source of truth for all color constants in the TUI.
 * Provides dark and light palettes for terminal background detection.
 */

import { RGBA } from "@opentui/core";

export interface ThemeColors {
  // Primary accent colors
  greenAccent: RGBA;
  cyanAccent: RGBA;

  // Text colors
  creamText: RGBA;
  primaryText: RGBA;
  secondaryText: RGBA;
  dimText: RGBA;

  // Semantic colors
  toolColor: RGBA;
  errorColor: RGBA;
  successColor: RGBA;

  // Warning/status colors
  yellowText: RGBA;
  orangeText: RGBA;
  redText: RGBA;

  // Code/syntax highlighting
  codeColor: RGBA;
  linkColor: RGBA;

  // UI element colors
  borderDark: RGBA;
  backgroundDark: RGBA;
  backgroundDarker: RGBA;

  // Modal/overlay colors
  overlayBg: RGBA;
  panelBg: RGBA;
  panelBorder: RGBA;
  selectedBg: RGBA;
}

export const darkColors: ThemeColors = {
  // Primary accent colors
  greenAccent: RGBA.fromInts(76, 175, 80, 255),
  cyanAccent: RGBA.fromInts(0, 188, 212, 255),

  // Text colors
  creamText: RGBA.fromInts(255, 248, 220, 255),
  primaryText: RGBA.fromInts(255, 255, 255, 255),
  secondaryText: RGBA.fromInts(170, 170, 170, 255),
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

  // Modal/overlay colors
  overlayBg: RGBA.fromInts(0, 0, 0, 200),
  panelBg: RGBA.fromInts(20, 20, 20, 255),
  panelBorder: RGBA.fromInts(60, 60, 60, 255),
  selectedBg: RGBA.fromInts(40, 40, 60, 255),
};

export const lightColors: ThemeColors = {
  // Primary accent colors
  greenAccent: RGBA.fromInts(34, 139, 34, 255),
  cyanAccent: RGBA.fromInts(0, 150, 170, 255),

  // Text colors
  creamText: RGBA.fromInts(30, 30, 30, 255),
  primaryText: RGBA.fromInts(0, 0, 0, 255),
  secondaryText: RGBA.fromInts(80, 80, 80, 255),
  dimText: RGBA.fromInts(100, 100, 100, 255),

  // Semantic colors
  toolColor: RGBA.fromInts(25, 100, 200, 255),
  errorColor: RGBA.fromInts(200, 40, 30, 255),
  successColor: RGBA.fromInts(34, 120, 34, 255),

  // Warning/status colors
  yellowText: RGBA.fromInts(180, 140, 0, 255),
  orangeText: RGBA.fromInts(200, 120, 0, 255),
  redText: RGBA.fromInts(200, 40, 30, 255),

  // Code/syntax highlighting
  codeColor: RGBA.fromInts(0, 128, 0, 255),
  linkColor: RGBA.fromInts(0, 100, 200, 255),

  // UI element colors
  borderDark: RGBA.fromInts(200, 200, 200, 255),
  backgroundDark: RGBA.fromInts(235, 235, 235, 255),
  backgroundDarker: RGBA.fromInts(245, 245, 245, 255),

  // Modal/overlay colors
  overlayBg: RGBA.fromInts(0, 0, 0, 100),
  panelBg: RGBA.fromInts(245, 245, 245, 255),
  panelBorder: RGBA.fromInts(180, 180, 180, 255),
  selectedBg: RGBA.fromInts(210, 220, 240, 255),
};

export type ColorName = keyof ThemeColors;
