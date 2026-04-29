/**
 * Catppuccin — Dark: Mocha, Light: Latte
 *
 * Sourced from https://github.com/catppuccin/catppuccin
 */

import { RGBA } from "@opentui/core";
import type { ThemeDefinition } from "../types";

export const catppuccin: ThemeDefinition = {
  name: "catppuccin",
  displayName: "Catppuccin",
  modes: ["dark", "light"],
  colors: {
    // ── Core UI ──────────────────────────────────────────────
    primary: {
      dark: RGBA.fromHex("#cba6f7"), // mauve (mocha)
      light: RGBA.fromHex("#8839ef"), // mauve (latte)
    },
    secondary: {
      dark: RGBA.fromHex("#89b4fa"), // blue (mocha)
      light: RGBA.fromHex("#1e66f5"), // blue (latte)
    },
    accent: {
      dark: RGBA.fromHex("#f5c2e7"), // pink (mocha)
      light: RGBA.fromHex("#ea76cb"), // pink (latte)
    },

    // ── Text ─────────────────────────────────────────────────
    text: {
      dark: RGBA.fromHex("#cdd6f4"), // text (mocha)
      light: RGBA.fromHex("#4c4f69"), // text (latte)
    },
    textMuted: {
      dark: RGBA.fromHex("#6c7086"), // overlay0 (mocha)
      light: RGBA.fromHex("#9ca0b0"), // overlay0 (latte)
    },

    // ── Backgrounds ──────────────────────────────────────────
    background: {
      dark: RGBA.fromHex("#1e1e2e"), // base (mocha)
      light: RGBA.fromHex("#eff1f5"), // base (latte)
    },
    backgroundPanel: {
      dark: RGBA.fromHex("#181825"), // mantle (mocha)
      light: RGBA.fromHex("#e6e9ef"), // mantle (latte)
    },
    backgroundElement: {
      dark: RGBA.fromHex("#313244"), // surface0 (mocha)
      light: RGBA.fromHex("#ccd0da"), // surface0 (latte)
    },
    backgroundOverlay: {
      dark: RGBA.fromInts(0, 0, 0, 200),
      light: RGBA.fromInts(0, 0, 0, 180),
    },
    backgroundSelected: {
      dark: RGBA.fromHex("#45475a"), // surface1 (mocha)
      light: RGBA.fromHex("#bcc0cc"), // surface1 (latte)
    },

    // ── Borders ──────────────────────────────────────────────
    border: {
      dark: RGBA.fromHex("#45475a"), // surface1 (mocha)
      light: RGBA.fromHex("#bcc0cc"), // surface1 (latte)
    },
    borderActive: {
      dark: RGBA.fromHex("#cba6f7"), // mauve (mocha)
      light: RGBA.fromHex("#8839ef"), // mauve (latte)
    },
    borderSubtle: {
      dark: RGBA.fromHex("#313244"), // surface0 (mocha)
      light: RGBA.fromHex("#ccd0da"), // surface0 (latte)
    },

    // ── Semantic Status ──────────────────────────────────────
    error: {
      dark: RGBA.fromHex("#f38ba8"), // red (mocha)
      light: RGBA.fromHex("#d20f39"), // red (latte)
    },
    warning: {
      dark: RGBA.fromHex("#f9e2af"), // yellow (mocha)
      light: RGBA.fromHex("#df8e1d"), // yellow (latte)
    },
    success: {
      dark: RGBA.fromHex("#a6e3a1"), // green (mocha)
      light: RGBA.fromHex("#40a02b"), // green (latte)
    },
    info: {
      dark: RGBA.fromHex("#89dceb"), // sky (mocha)
      light: RGBA.fromHex("#04a5e5"), // sky (latte)
    },

    // ── Permission Tiers ─────────────────────────────────────
    tierSafe: {
      dark: RGBA.fromHex("#a6e3a1"), // green (mocha)
      light: RGBA.fromHex("#40a02b"), // green (latte)
    },
    tierModerate: {
      dark: RGBA.fromHex("#f9e2af"), // yellow (mocha)
      light: RGBA.fromHex("#df8e1d"), // yellow (latte)
    },
    tierRisky: {
      dark: RGBA.fromHex("#fab387"), // peach (mocha)
      light: RGBA.fromHex("#fe640b"), // peach (latte)
    },
    tierDangerous: {
      dark: RGBA.fromHex("#f38ba8"), // red (mocha)
      light: RGBA.fromHex("#d20f39"), // red (latte)
    },

    // ── Markdown Rendering ───────────────────────────────────
    markdownCode: {
      dark: RGBA.fromHex("#a6e3a1"), // green (mocha)
      light: RGBA.fromHex("#40a02b"), // green (latte)
    },
    markdownLink: {
      dark: RGBA.fromHex("#89b4fa"), // blue (mocha)
      light: RGBA.fromHex("#1e66f5"), // blue (latte)
    },
    markdownHeading: {
      dark: RGBA.fromHex("#cba6f7"), // mauve (mocha)
      light: RGBA.fromHex("#8839ef"), // mauve (latte)
    },
    markdownStrong: {
      dark: RGBA.fromHex("#fab387"), // peach (mocha)
      light: RGBA.fromHex("#fe640b"), // peach (latte)
    },
    markdownEmph: {
      dark: RGBA.fromHex("#f9e2af"), // yellow (mocha)
      light: RGBA.fromHex("#df8e1d"), // yellow (latte)
    },

    // ── Syntax Highlighting ──────────────────────────────────
    syntaxKeyword: {
      dark: RGBA.fromHex("#cba6f7"), // mauve (mocha)
      light: RGBA.fromHex("#8839ef"), // mauve (latte)
    },
    syntaxString: {
      dark: RGBA.fromHex("#a6e3a1"), // green (mocha)
      light: RGBA.fromHex("#40a02b"), // green (latte)
    },
    syntaxComment: {
      dark: RGBA.fromHex("#6c7086"), // overlay0 (mocha)
      light: RGBA.fromHex("#9ca0b0"), // overlay0 (latte)
    },
    syntaxNumber: {
      dark: RGBA.fromHex("#fab387"), // peach (mocha)
      light: RGBA.fromHex("#fe640b"), // peach (latte)
    },
    syntaxFunction: {
      dark: RGBA.fromHex("#89b4fa"), // blue (mocha)
      light: RGBA.fromHex("#1e66f5"), // blue (latte)
    },
    syntaxType: {
      dark: RGBA.fromHex("#f9e2af"), // yellow (mocha)
      light: RGBA.fromHex("#df8e1d"), // yellow (latte)
    },
    syntaxTag: {
      dark: RGBA.fromHex("#f38ba8"), // red (mocha)
      light: RGBA.fromHex("#d20f39"), // red (latte)
    },
    syntaxAttr: {
      dark: RGBA.fromHex("#94e2d5"), // teal (mocha)
      light: RGBA.fromHex("#179299"), // teal (latte)
    },
    syntaxPunctuation: {
      dark: RGBA.fromHex("#a6adc8"), // subtext0 (mocha)
      light: RGBA.fromHex("#6c6f85"), // subtext0 (latte)
    },

    // ── Diff ─────────────────────────────────────────────────
    diffAdded: {
      dark: RGBA.fromHex("#a6e3a1"), // green (mocha)
      light: RGBA.fromHex("#40a02b"), // green (latte)
    },
    diffRemoved: {
      dark: RGBA.fromHex("#f38ba8"), // red (mocha)
      light: RGBA.fromHex("#d20f39"), // red (latte)
    },
    diffAddedBg: {
      dark: RGBA.fromHex("#1e3a2f"),
      light: RGBA.fromHex("#d5e8d4"),
    },
    diffRemovedBg: {
      dark: RGBA.fromHex("#3b2030"),
      light: RGBA.fromHex("#f5d5db"),
    },
  },
};
