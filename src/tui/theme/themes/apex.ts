/**
 * Apex — Default Theme
 *
 * Dark mode preserves the existing green/cream palette exactly.
 * Light mode inverts the palette while keeping the green accent identity.
 */

import { RGBA } from "@opentui/core";
import type { ThemeDefinition } from "../types";

export const apex: ThemeDefinition = {
  name: "apex",
  displayName: "Apex",
  modes: ["dark", "light"],
  colors: {
    // ── Core UI ──────────────────────────────────────────────
    primary: {
      dark: RGBA.fromInts(76, 175, 80, 255), // greenAccent
      light: RGBA.fromInts(46, 125, 50, 255), // darker green for light bg
    },
    secondary: {
      dark: RGBA.fromInts(0, 188, 212, 255), // cyanAccent
      light: RGBA.fromInts(0, 131, 148, 255), // darker cyan for light bg
    },
    accent: {
      dark: RGBA.fromInts(100, 181, 246, 255), // blueText
      light: RGBA.fromInts(25, 118, 210, 255), // darker blue for light bg
    },

    // ── Text ─────────────────────────────────────────────────
    text: {
      dark: RGBA.fromInts(255, 248, 220, 255), // creamText
      light: RGBA.fromInts(30, 30, 30, 255), // near-black on light bg
    },
    textMuted: {
      dark: RGBA.fromInts(120, 120, 120, 255), // dimText
      light: RGBA.fromInts(110, 110, 110, 255),
    },

    // ── Backgrounds ──────────────────────────────────────────
    background: {
      dark: RGBA.fromInts(10, 10, 10, 255), // backgroundDarker
      light: RGBA.fromInts(250, 250, 247, 255), // warm off-white
    },
    backgroundPanel: {
      dark: RGBA.fromInts(20, 20, 20, 255),
      light: RGBA.fromInts(240, 240, 237, 255),
    },
    backgroundElement: {
      dark: RGBA.fromInts(40, 40, 40, 255), // backgroundDark
      light: RGBA.fromInts(230, 230, 227, 255),
    },
    backgroundOverlay: {
      dark: RGBA.fromInts(0, 0, 0, 200),
      light: RGBA.fromInts(0, 0, 0, 180),
    },
    backgroundSelected: {
      dark: RGBA.fromInts(40, 40, 60, 255),
      light: RGBA.fromInts(210, 230, 212, 255), // green-tinted selection
    },

    // ── Borders ──────────────────────────────────────────────
    border: {
      dark: RGBA.fromInts(60, 60, 60, 255),
      light: RGBA.fromInts(200, 200, 200, 255),
    },
    borderActive: {
      dark: RGBA.fromInts(76, 175, 80, 255), // matches primary
      light: RGBA.fromInts(46, 125, 50, 255),
    },
    borderSubtle: {
      dark: RGBA.fromInts(30, 30, 30, 255), // borderDark
      light: RGBA.fromInts(225, 225, 225, 255),
    },

    // ── Semantic Status ──────────────────────────────────────
    error: {
      dark: RGBA.fromInts(244, 67, 54, 255), // errorColor / redText
      light: RGBA.fromInts(198, 40, 40, 255),
    },
    warning: {
      dark: RGBA.fromInts(255, 235, 59, 255), // yellowText
      light: RGBA.fromInts(175, 160, 0, 255),
    },
    success: {
      dark: RGBA.fromInts(100, 200, 100, 255), // successColor
      light: RGBA.fromInts(46, 125, 50, 255),
    },
    info: {
      dark: RGBA.fromInts(100, 180, 255, 255), // toolColor
      light: RGBA.fromInts(25, 118, 210, 255),
    },

    // ── Permission Tiers ─────────────────────────────────────
    tierSafe: {
      dark: RGBA.fromInts(76, 175, 80, 255), // green
      light: RGBA.fromInts(46, 125, 50, 255),
    },
    tierModerate: {
      dark: RGBA.fromInts(255, 235, 59, 255), // yellow
      light: RGBA.fromInts(175, 160, 0, 255),
    },
    tierRisky: {
      dark: RGBA.fromInts(255, 152, 0, 255), // orange
      light: RGBA.fromInts(200, 120, 0, 255),
    },
    tierDangerous: {
      dark: RGBA.fromInts(244, 67, 54, 255), // red
      light: RGBA.fromInts(198, 40, 40, 255),
    },

    // ── Markdown Rendering ───────────────────────────────────
    markdownCode: {
      dark: RGBA.fromInts(100, 255, 100, 255), // codeColor
      light: RGBA.fromInts(36, 130, 36, 255),
    },
    markdownLink: {
      dark: RGBA.fromInts(100, 200, 255, 255), // linkColor
      light: RGBA.fromInts(25, 118, 210, 255),
    },
    markdownHeading: {
      dark: RGBA.fromInts(0, 188, 212, 255), // secondary/cyan
      light: RGBA.fromInts(0, 131, 148, 255),
    },
    markdownStrong: {
      dark: RGBA.fromInts(255, 248, 220, 255), // creamText (bold stands out)
      light: RGBA.fromInts(20, 20, 20, 255),
    },
    markdownEmph: {
      dark: RGBA.fromInts(255, 235, 59, 255), // yellowText
      light: RGBA.fromInts(175, 160, 0, 255),
    },

    // ── Syntax Highlighting ──────────────────────────────────
    syntaxKeyword: {
      dark: RGBA.fromInts(170, 140, 190, 255), // muted lavender
      light: RGBA.fromInts(100, 70, 120, 255), // muted plum
    },
    syntaxString: {
      dark: RGBA.fromInts(140, 170, 130, 255), // muted sage
      light: RGBA.fromInts(60, 100, 60, 255), // muted forest
    },
    syntaxComment: {
      dark: RGBA.fromInts(110, 118, 129, 255), // gray
      light: RGBA.fromInts(120, 125, 132, 255), // mid gray
    },
    syntaxNumber: {
      dark: RGBA.fromInts(180, 150, 120, 255), // muted tan
      light: RGBA.fromInts(130, 95, 50, 255), // muted brown
    },
    syntaxFunction: {
      dark: RGBA.fromInts(140, 170, 200, 255), // muted steel blue
      light: RGBA.fromInts(50, 90, 150, 255), // muted navy
    },
    syntaxType: {
      dark: RGBA.fromInts(130, 170, 175, 255), // muted teal
      light: RGBA.fromInts(40, 100, 110, 255), // muted teal
    },
    syntaxTag: {
      dark: RGBA.fromInts(180, 130, 130, 255), // muted rose
      light: RGBA.fromInts(140, 60, 65, 255), // muted burgundy
    },
    syntaxAttr: {
      dark: RGBA.fromInts(180, 170, 140, 255), // muted sand
      light: RGBA.fromInts(110, 95, 50, 255), // muted olive
    },
    syntaxPunctuation: {
      dark: RGBA.fromInts(155, 162, 172, 255), // light gray
      light: RGBA.fromInts(90, 95, 105, 255), // dark gray
    },

    // ── Diff ─────────────────────────────────────────────────
    diffAdded: {
      dark: RGBA.fromInts(76, 175, 80, 255),
      light: RGBA.fromInts(30, 114, 92, 255),
    },
    diffRemoved: {
      dark: RGBA.fromInts(244, 67, 54, 255),
      light: RGBA.fromInts(197, 59, 83, 255),
    },
    diffAddedBg: {
      dark: RGBA.fromInts(32, 48, 59, 255),
      light: RGBA.fromInts(213, 229, 213, 255),
    },
    diffRemovedBg: {
      dark: RGBA.fromInts(55, 34, 44, 255),
      light: RGBA.fromInts(247, 216, 219, 255),
    },
  },
};
