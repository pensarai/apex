/**
 * Tokyo Night — Dark: Night, Light: Day
 *
 * Sourced from https://github.com/folke/tokyonight.nvim
 */

import { RGBA } from "@opentui/core";
import type { ThemeDefinition } from "../types";

export const tokyonight: ThemeDefinition = {
  name: "tokyonight",
  displayName: "Tokyo Night",
  modes: ["dark", "light"],
  colors: {
    // ── Core UI ──────────────────────────────────────────────
    primary: {
      dark: RGBA.fromHex("#7aa2f7"), // blue
      light: RGBA.fromHex("#2e7de9"),
    },
    secondary: {
      dark: RGBA.fromHex("#bb9af7"), // magenta/purple
      light: RGBA.fromHex("#9854f1"),
    },
    accent: {
      dark: RGBA.fromHex("#ff9e64"), // orange
      light: RGBA.fromHex("#b15c00"),
    },

    // ── Text ─────────────────────────────────────────────────
    text: {
      dark: RGBA.fromHex("#c0caf5"), // fg
      light: RGBA.fromHex("#3760bf"),
    },
    textMuted: {
      dark: RGBA.fromHex("#565f89"), // comment
      light: RGBA.fromHex("#8990b3"),
    },

    // ── Backgrounds ──────────────────────────────────────────
    background: {
      dark: RGBA.fromHex("#1a1b26"), // bg
      light: RGBA.fromHex("#e1e2e7"),
    },
    backgroundPanel: {
      dark: RGBA.fromHex("#16161e"), // bg_dark
      light: RGBA.fromHex("#d0d5e3"),
    },
    backgroundElement: {
      dark: RGBA.fromHex("#292e42"), // bg_highlight
      light: RGBA.fromHex("#c4c8da"),
    },
    backgroundOverlay: {
      dark: RGBA.fromInts(0, 0, 0, 200),
      light: RGBA.fromInts(255, 255, 255, 200),
    },
    backgroundSelected: {
      dark: RGBA.fromHex("#283457"),
      light: RGBA.fromHex("#b6bfe2"),
    },

    // ── Borders ──────────────────────────────────────────────
    border: {
      dark: RGBA.fromHex("#3b4261"),
      light: RGBA.fromHex("#a8aecb"),
    },
    borderActive: {
      dark: RGBA.fromHex("#7aa2f7"), // primary
      light: RGBA.fromHex("#2e7de9"),
    },
    borderSubtle: {
      dark: RGBA.fromHex("#292e42"),
      light: RGBA.fromHex("#c4c8da"),
    },

    // ── Semantic Status ──────────────────────────────────────
    error: {
      dark: RGBA.fromHex("#f7768e"), // red
      light: RGBA.fromHex("#c64343"),
    },
    warning: {
      dark: RGBA.fromHex("#e0af68"), // yellow
      light: RGBA.fromHex("#8c6c3e"),
    },
    success: {
      dark: RGBA.fromHex("#9ece6a"), // green
      light: RGBA.fromHex("#587539"),
    },
    info: {
      dark: RGBA.fromHex("#7dcfff"), // cyan
      light: RGBA.fromHex("#07879d"),
    },

    // ── Permission Tiers ─────────────────────────────────────
    tierSafe: {
      dark: RGBA.fromHex("#9ece6a"),
      light: RGBA.fromHex("#587539"),
    },
    tierModerate: {
      dark: RGBA.fromHex("#e0af68"),
      light: RGBA.fromHex("#8c6c3e"),
    },
    tierRisky: {
      dark: RGBA.fromHex("#ff9e64"),
      light: RGBA.fromHex("#b15c00"),
    },
    tierDangerous: {
      dark: RGBA.fromHex("#f7768e"),
      light: RGBA.fromHex("#c64343"),
    },

    // ── Markdown Rendering ───────────────────────────────────
    markdownCode: {
      dark: RGBA.fromHex("#9ece6a"),
      light: RGBA.fromHex("#587539"),
    },
    markdownLink: {
      dark: RGBA.fromHex("#7dcfff"),
      light: RGBA.fromHex("#07879d"),
    },
    markdownHeading: {
      dark: RGBA.fromHex("#bb9af7"),
      light: RGBA.fromHex("#9854f1"),
    },
    markdownStrong: {
      dark: RGBA.fromHex("#ff9e64"),
      light: RGBA.fromHex("#b15c00"),
    },
    markdownEmph: {
      dark: RGBA.fromHex("#e0af68"),
      light: RGBA.fromHex("#8c6c3e"),
    },

    // ── Diff ─────────────────────────────────────────────────
    diffAdded: {
      dark: RGBA.fromHex("#449dab"),
      light: RGBA.fromHex("#1e725c"),
    },
    diffRemoved: {
      dark: RGBA.fromHex("#914c54"),
      light: RGBA.fromHex("#c53b53"),
    },
    diffAddedBg: {
      dark: RGBA.fromHex("#20303b"),
      light: RGBA.fromHex("#d5e5d5"),
    },
    diffRemovedBg: {
      dark: RGBA.fromHex("#37222c"),
      light: RGBA.fromHex("#f7d8db"),
    },
  },
};
