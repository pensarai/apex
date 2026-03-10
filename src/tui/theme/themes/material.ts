/**
 * Material — Dark: Oceanic, Light: Lighter
 *
 * Sourced from https://github.com/marko-cerovac/material.nvim
 * and https://github.com/kaicataldo/material.vim
 */

import { RGBA } from "@opentui/core";
import type { ThemeDefinition } from "../types";

export const material: ThemeDefinition = {
  name: "material",
  displayName: "Material",
  modes: ["dark", "light"],
  colors: {
    // ── Core UI ──────────────────────────────────────────────
    primary: {
      dark: RGBA.fromHex("#82aaff"), // blue
      light: RGBA.fromHex("#6182b8"),
    },
    secondary: {
      dark: RGBA.fromHex("#c792ea"), // purple
      light: RGBA.fromHex("#7c4dff"),
    },
    accent: {
      dark: RGBA.fromHex("#f78c6c"), // orange
      light: RGBA.fromHex("#e2931d"),
    },

    // ── Text ─────────────────────────────────────────────────
    text: {
      dark: RGBA.fromHex("#eeffff"), // fg
      light: RGBA.fromHex("#546e7a"),
    },
    textMuted: {
      dark: RGBA.fromHex("#546e7a"), // comment
      light: RGBA.fromHex("#90a4ae"),
    },

    // ── Backgrounds ──────────────────────────────────────────
    background: {
      dark: RGBA.fromHex("#263238"), // bg (oceanic)
      light: RGBA.fromHex("#fafafa"),
    },
    backgroundPanel: {
      dark: RGBA.fromHex("#1e272c"),
      light: RGBA.fromHex("#f2f2f2"),
    },
    backgroundElement: {
      dark: RGBA.fromHex("#2e3c43"),
      light: RGBA.fromHex("#eaeaea"),
    },
    backgroundOverlay: {
      dark: RGBA.fromInts(0, 0, 0, 200),
      light: RGBA.fromInts(0, 0, 0, 180),
    },
    backgroundSelected: {
      dark: RGBA.fromHex("#364850"),
      light: RGBA.fromHex("#e0e0e0"),
    },

    // ── Borders ──────────────────────────────────────────────
    border: {
      dark: RGBA.fromHex("#455a64"),
      light: RGBA.fromHex("#ccd7da"),
    },
    borderActive: {
      dark: RGBA.fromHex("#82aaff"),
      light: RGBA.fromHex("#6182b8"),
    },
    borderSubtle: {
      dark: RGBA.fromHex("#2e3c43"),
      light: RGBA.fromHex("#eaeaea"),
    },

    // ── Semantic Status ──────────────────────────────────────
    error: {
      dark: RGBA.fromHex("#ff5370"), // red
      light: RGBA.fromHex("#e53935"),
    },
    warning: {
      dark: RGBA.fromHex("#ffcb6b"), // yellow
      light: RGBA.fromHex("#e2931d"),
    },
    success: {
      dark: RGBA.fromHex("#c3e88d"), // green
      light: RGBA.fromHex("#91b859"),
    },
    info: {
      dark: RGBA.fromHex("#89ddff"), // cyan
      light: RGBA.fromHex("#39adb5"),
    },

    // ── Permission Tiers ─────────────────────────────────────
    tierSafe: {
      dark: RGBA.fromHex("#c3e88d"),
      light: RGBA.fromHex("#91b859"),
    },
    tierModerate: {
      dark: RGBA.fromHex("#ffcb6b"),
      light: RGBA.fromHex("#e2931d"),
    },
    tierRisky: {
      dark: RGBA.fromHex("#f78c6c"),
      light: RGBA.fromHex("#f76d47"),
    },
    tierDangerous: {
      dark: RGBA.fromHex("#ff5370"),
      light: RGBA.fromHex("#e53935"),
    },

    // ── Markdown Rendering ───────────────────────────────────
    markdownCode: {
      dark: RGBA.fromHex("#c3e88d"),
      light: RGBA.fromHex("#91b859"),
    },
    markdownLink: {
      dark: RGBA.fromHex("#82aaff"),
      light: RGBA.fromHex("#6182b8"),
    },
    markdownHeading: {
      dark: RGBA.fromHex("#c792ea"),
      light: RGBA.fromHex("#7c4dff"),
    },
    markdownStrong: {
      dark: RGBA.fromHex("#f78c6c"),
      light: RGBA.fromHex("#e2931d"),
    },
    markdownEmph: {
      dark: RGBA.fromHex("#ffcb6b"),
      light: RGBA.fromHex("#e2931d"),
    },

    // ── Diff ─────────────────────────────────────────────────
    diffAdded: {
      dark: RGBA.fromHex("#c3e88d"),
      light: RGBA.fromHex("#91b859"),
    },
    diffRemoved: {
      dark: RGBA.fromHex("#ff5370"),
      light: RGBA.fromHex("#e53935"),
    },
    diffAddedBg: {
      dark: RGBA.fromHex("#1e3325"),
      light: RGBA.fromHex("#dfedc8"),
    },
    diffRemovedBg: {
      dark: RGBA.fromHex("#3a1a22"),
      light: RGBA.fromHex("#f8d5d0"),
    },
  },
};
