/**
 * Ayu — Dark: Ayu Dark, Light: Ayu Light
 *
 * Sourced from https://github.com/ayu-theme
 */

import { RGBA } from "@opentui/core";
import type { ThemeDefinition } from "../types";

export const ayu: ThemeDefinition = {
  name: "ayu",
  displayName: "Ayu",
  modes: ["dark", "light"],
  colors: {
    // ── Core UI ──────────────────────────────────────────────
    primary: {
      dark: RGBA.fromHex("#e6b450"), // accent (dark)
      light: RGBA.fromHex("#ff9940"), // accent (light)
    },
    secondary: {
      dark: RGBA.fromHex("#39bae6"), // blue
      light: RGBA.fromHex("#399ee6"),
    },
    accent: {
      dark: RGBA.fromHex("#f29668"), // orange
      light: RGBA.fromHex("#fa8d3e"),
    },

    // ── Text ─────────────────────────────────────────────────
    text: {
      dark: RGBA.fromHex("#bfbdb6"), // fg
      light: RGBA.fromHex("#5c6166"),
    },
    textMuted: {
      dark: RGBA.fromHex("#636a72"), // comment
      light: RGBA.fromHex("#8a9199"),
    },

    // ── Backgrounds ──────────────────────────────────────────
    background: {
      dark: RGBA.fromHex("#0d1017"), // bg (dark)
      light: RGBA.fromHex("#fafafa"),
    },
    backgroundPanel: {
      dark: RGBA.fromHex("#0b0e14"),
      light: RGBA.fromHex("#f0f0f0"),
    },
    backgroundElement: {
      dark: RGBA.fromHex("#131721"),
      light: RGBA.fromHex("#e8e8e8"),
    },
    backgroundOverlay: {
      dark: RGBA.fromInts(0, 0, 0, 200),
      light: RGBA.fromInts(0, 0, 0, 180),
    },
    backgroundSelected: {
      dark: RGBA.fromHex("#1a1f29"),
      light: RGBA.fromHex("#d8d8d8"),
    },

    // ── Borders ──────────────────────────────────────────────
    border: {
      dark: RGBA.fromHex("#2d333b"),
      light: RGBA.fromHex("#d0cdc8"),
    },
    borderActive: {
      dark: RGBA.fromHex("#e6b450"),
      light: RGBA.fromHex("#ff9940"),
    },
    borderSubtle: {
      dark: RGBA.fromHex("#131721"),
      light: RGBA.fromHex("#e8e8e8"),
    },

    // ── Semantic Status ──────────────────────────────────────
    error: {
      dark: RGBA.fromHex("#d95757"), // red
      light: RGBA.fromHex("#f51818"),
    },
    warning: {
      dark: RGBA.fromHex("#e6b450"), // yellow
      light: RGBA.fromHex("#f2ae49"),
    },
    success: {
      dark: RGBA.fromHex("#7fd962"), // green
      light: RGBA.fromHex("#6cbf43"),
    },
    info: {
      dark: RGBA.fromHex("#39bae6"), // blue
      light: RGBA.fromHex("#399ee6"),
    },

    // ── Permission Tiers ─────────────────────────────────────
    tierSafe: {
      dark: RGBA.fromHex("#7fd962"),
      light: RGBA.fromHex("#6cbf43"),
    },
    tierModerate: {
      dark: RGBA.fromHex("#e6b450"),
      light: RGBA.fromHex("#f2ae49"),
    },
    tierRisky: {
      dark: RGBA.fromHex("#f29668"),
      light: RGBA.fromHex("#fa8d3e"),
    },
    tierDangerous: {
      dark: RGBA.fromHex("#d95757"),
      light: RGBA.fromHex("#f51818"),
    },

    // ── Markdown Rendering ───────────────────────────────────
    markdownCode: {
      dark: RGBA.fromHex("#7fd962"),
      light: RGBA.fromHex("#6cbf43"),
    },
    markdownLink: {
      dark: RGBA.fromHex("#39bae6"),
      light: RGBA.fromHex("#399ee6"),
    },
    markdownHeading: {
      dark: RGBA.fromHex("#f29668"),
      light: RGBA.fromHex("#fa8d3e"),
    },
    markdownStrong: {
      dark: RGBA.fromHex("#e6b450"),
      light: RGBA.fromHex("#f2ae49"),
    },
    markdownEmph: {
      dark: RGBA.fromHex("#d2a6ff"), // purple
      light: RGBA.fromHex("#a37acc"),
    },

    // ── Syntax Highlighting ──────────────────────────────────
    syntaxKeyword: {
      dark: RGBA.fromHex("#ff8f40"), // orange (keyword)
      light: RGBA.fromHex("#d75d06"),
    },
    syntaxString: {
      dark: RGBA.fromHex("#aad94c"), // green
      light: RGBA.fromHex("#678a00"),
    },
    syntaxComment: {
      dark: RGBA.fromHex("#636a72"), // comment
      light: RGBA.fromHex("#8a9199"),
    },
    syntaxNumber: {
      dark: RGBA.fromHex("#e6b450"), // yellow/accent
      light: RGBA.fromHex("#996bc6"), // purple in light
    },
    syntaxFunction: {
      dark: RGBA.fromHex("#ffb454"), // amber (function)
      light: RGBA.fromHex("#b4710d"),
    },
    syntaxType: {
      dark: RGBA.fromHex("#39bae6"), // blue (type)
      light: RGBA.fromHex("#1a85d2"),
    },
    syntaxTag: {
      dark: RGBA.fromHex("#39bae6"), // blue (tag)
      light: RGBA.fromHex("#1a85d2"),
    },
    syntaxAttr: {
      dark: RGBA.fromHex("#f29668"), // orange (attr)
      light: RGBA.fromHex("#b37623"),
    },
    syntaxPunctuation: {
      dark: RGBA.fromHex("#bfbdb6"), // fg
      light: RGBA.fromHex("#5c6166"),
    },

    // ── Diff ─────────────────────────────────────────────────
    diffAdded: {
      dark: RGBA.fromHex("#7fd962"),
      light: RGBA.fromHex("#6cbf43"),
    },
    diffRemoved: {
      dark: RGBA.fromHex("#d95757"),
      light: RGBA.fromHex("#f51818"),
    },
    diffAddedBg: {
      dark: RGBA.fromHex("#1a2e18"),
      light: RGBA.fromHex("#d8edcf"),
    },
    diffRemovedBg: {
      dark: RGBA.fromHex("#2e1a1a"),
      light: RGBA.fromHex("#f5d5d5"),
    },
  },
};
