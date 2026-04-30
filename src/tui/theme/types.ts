/**
 * Theme System Type Definitions
 *
 * Core types for the Apex TUI theme system. Every color used in the TUI
 * maps to one of the semantic tokens defined in ThemeColors.
 */

import type { RGBA } from "@opentui/core";

/** Dark or light color mode */
export type ColorMode = "dark" | "light";

/**
 * A color value that may vary between dark and light modes.
 * Plain RGBA is used for both modes; { dark, light } provides per-mode values.
 */
export type ThemeColorValue = RGBA | { dark: RGBA; light: RGBA };

/**
 * Complete set of semantic color tokens for the Apex TUI.
 * Every color used anywhere in the TUI must map to one of these tokens.
 */
export interface ThemeColors {
  // ── Core UI ──────────────────────────────────────────────
  /** Primary accent color (buttons, highlights, active elements) */
  primary: RGBA;
  /** Secondary accent color (links, secondary actions) */
  secondary: RGBA;
  /** Tertiary accent (decorative, less prominent highlights) */
  accent: RGBA;

  // ── Text ─────────────────────────────────────────────────
  /** Default text color */
  text: RGBA;
  /** Muted/dimmed text (timestamps, secondary info, placeholders) */
  textMuted: RGBA;

  // ── Backgrounds ──────────────────────────────────────────
  /** Main application background */
  background: RGBA;
  /** Panel/sidebar background (slightly lighter/darker than main) */
  backgroundPanel: RGBA;
  /** UI element background (inputs, cards, menus) */
  backgroundElement: RGBA;
  /** Overlay background (modals, dialogs — typically semi-transparent) */
  backgroundOverlay: RGBA;
  /** Selected/highlighted item background */
  backgroundSelected: RGBA;

  // ── Borders ──────────────────────────────────────────────
  /** Default border color */
  border: RGBA;
  /** Active/focused border color */
  borderActive: RGBA;
  /** Subtle/muted border color */
  borderSubtle: RGBA;

  // ── Semantic Status ──────────────────────────────────────
  /** Error state (failed operations, validation errors) */
  error: RGBA;
  /** Warning state (risky actions, caution) */
  warning: RGBA;
  /** Success state (completed, approved) */
  success: RGBA;
  /** Informational (neutral status, tool calls) */
  info: RGBA;

  // ── Permission Tiers ─────────────────────────────────────
  /** Safe tier (1-2) — typically green */
  tierSafe: RGBA;
  /** Moderate tier (3) — typically yellow */
  tierModerate: RGBA;
  /** Risky tier (4) — typically orange */
  tierRisky: RGBA;
  /** Dangerous tier (5) — typically red */
  tierDangerous: RGBA;

  // ── Markdown Rendering ───────────────────────────────────
  /** Inline code text */
  markdownCode: RGBA;
  /** Link text */
  markdownLink: RGBA;
  /** Heading text */
  markdownHeading: RGBA;
  /** Bold text */
  markdownStrong: RGBA;
  /** Italic text */
  markdownEmph: RGBA;

  // ── Syntax Highlighting ──────────────────────────────────
  /** Keywords, control flow, built-ins */
  syntaxKeyword: RGBA;
  /** String literals */
  syntaxString: RGBA;
  /** Comments */
  syntaxComment: RGBA;
  /** Numeric literals */
  syntaxNumber: RGBA;
  /** Function names and calls */
  syntaxFunction: RGBA;
  /** Type names, interfaces, classes */
  syntaxType: RGBA;
  /** HTML/XML tags, variables */
  syntaxTag: RGBA;
  /** Attributes, parameters, properties */
  syntaxAttr: RGBA;
  /** Punctuation, operators */
  syntaxPunctuation: RGBA;

  // ── Diff ─────────────────────────────────────────────────
  /** Added line foreground */
  diffAdded: RGBA;
  /** Removed line foreground */
  diffRemoved: RGBA;
  /** Added line background */
  diffAddedBg: RGBA;
  /** Removed line background */
  diffRemovedBg: RGBA;
}

/**
 * Raw theme colors before mode resolution — each token can be a single RGBA
 * (used for both modes) or a { dark, light } object.
 */
export type ThemeColorsInput = {
  [K in keyof ThemeColors]: ThemeColorValue;
};

/**
 * A complete theme definition with metadata.
 * Each theme provides both dark and light colors via per-token { dark, light } objects.
 * A global mode toggle selects which variant is used at runtime.
 */
export interface ThemeDefinition {
  /** Unique theme identifier (kebab-case) */
  name: string;
  /** Human-readable display name */
  displayName: string;
  /** Which modes this theme supports */
  modes: ColorMode[];
  /** The color token values — each can be RGBA or { dark, light } */
  colors: ThemeColorsInput;
}
