/**
 * Dracula — Dark: Canonical, Light: Designed
 *
 * Dark sourced from https://github.com/dracula/dracula-theme
 * Light variant designed to preserve Dracula's purple/pink/green accent identity.
 */

import { RGBA } from "@opentui/core";
import type { ThemeDefinition } from "../types";

export const dracula: ThemeDefinition = {
  name: "dracula",
  displayName: "Dracula",
  modes: ["dark", "light"],
  colors: {
    // ── Core UI ──────────────────────────────────────────────
    primary: {
      dark: RGBA.fromHex("#bd93f9"), // purple
      light: RGBA.fromHex("#7c3aed"),
    },
    secondary: {
      dark: RGBA.fromHex("#ff79c6"), // pink
      light: RGBA.fromHex("#d6336c"),
    },
    accent: {
      dark: RGBA.fromHex("#ffb86c"), // orange
      light: RGBA.fromHex("#c2410c"),
    },

    // ── Text ─────────────────────────────────────────────────
    text: {
      dark: RGBA.fromHex("#f8f8f2"), // fg
      light: RGBA.fromHex("#282a36"),
    },
    textMuted: {
      dark: RGBA.fromHex("#6272a4"), // comment
      light: RGBA.fromHex("#8b95b8"),
    },

    // ── Backgrounds ──────────────────────────────────────────
    background: {
      dark: RGBA.fromHex("#282a36"), // bg
      light: RGBA.fromHex("#f8f8f2"),
    },
    backgroundPanel: {
      dark: RGBA.fromHex("#21222c"),
      light: RGBA.fromHex("#ecedf2"),
    },
    backgroundElement: {
      dark: RGBA.fromHex("#44475a"), // selection
      light: RGBA.fromHex("#d6d9e8"),
    },
    backgroundOverlay: {
      dark: RGBA.fromInts(0, 0, 0, 200),
      light: RGBA.fromInts(0, 0, 0, 180),
    },
    backgroundSelected: {
      dark: RGBA.fromHex("#44475a"), // selection
      light: RGBA.fromHex("#d0d3e4"),
    },

    // ── Borders ──────────────────────────────────────────────
    border: {
      dark: RGBA.fromHex("#6272a4"), // comment
      light: RGBA.fromHex("#c0c5d8"),
    },
    borderActive: {
      dark: RGBA.fromHex("#bd93f9"), // purple
      light: RGBA.fromHex("#7c3aed"),
    },
    borderSubtle: {
      dark: RGBA.fromHex("#44475a"),
      light: RGBA.fromHex("#d6d9e8"),
    },

    // ── Semantic Status ──────────────────────────────────────
    error: {
      dark: RGBA.fromHex("#ff5555"), // red
      light: RGBA.fromHex("#c62828"),
    },
    warning: {
      dark: RGBA.fromHex("#f1fa8c"), // yellow
      light: RGBA.fromHex("#9a7b00"),
    },
    success: {
      dark: RGBA.fromHex("#50fa7b"), // green
      light: RGBA.fromHex("#1b8332"),
    },
    info: {
      dark: RGBA.fromHex("#8be9fd"), // cyan
      light: RGBA.fromHex("#0e7490"),
    },

    // ── Permission Tiers ─────────────────────────────────────
    tierSafe: {
      dark: RGBA.fromHex("#50fa7b"),
      light: RGBA.fromHex("#1b8332"),
    },
    tierModerate: {
      dark: RGBA.fromHex("#f1fa8c"),
      light: RGBA.fromHex("#9a7b00"),
    },
    tierRisky: {
      dark: RGBA.fromHex("#ffb86c"),
      light: RGBA.fromHex("#c2410c"),
    },
    tierDangerous: {
      dark: RGBA.fromHex("#ff5555"),
      light: RGBA.fromHex("#c62828"),
    },

    // ── Markdown Rendering ───────────────────────────────────
    markdownCode: {
      dark: RGBA.fromHex("#50fa7b"), // green
      light: RGBA.fromHex("#1b8332"),
    },
    markdownLink: {
      dark: RGBA.fromHex("#8be9fd"), // cyan
      light: RGBA.fromHex("#0e7490"),
    },
    markdownHeading: {
      dark: RGBA.fromHex("#bd93f9"), // purple
      light: RGBA.fromHex("#7c3aed"),
    },
    markdownStrong: {
      dark: RGBA.fromHex("#ffb86c"), // orange
      light: RGBA.fromHex("#c2410c"),
    },
    markdownEmph: {
      dark: RGBA.fromHex("#f1fa8c"), // yellow
      light: RGBA.fromHex("#9a7b00"),
    },

    // ── Diff ─────────────────────────────────────────────────
    diffAdded: {
      dark: RGBA.fromHex("#50fa7b"),
      light: RGBA.fromHex("#1b8332"),
    },
    diffRemoved: {
      dark: RGBA.fromHex("#ff5555"),
      light: RGBA.fromHex("#c62828"),
    },
    diffAddedBg: {
      dark: RGBA.fromHex("#1a3a2a"),
      light: RGBA.fromHex("#d4edda"),
    },
    diffRemovedBg: {
      dark: RGBA.fromHex("#3a1a1a"),
      light: RGBA.fromHex("#f8d7da"),
    },
  },
};
