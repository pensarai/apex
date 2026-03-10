/**
 * Rose Pine — Dark: Main, Light: Dawn
 *
 * Sourced from https://github.com/rose-pine/palette
 */

import { RGBA } from "@opentui/core";
import type { ThemeDefinition } from "../types";

export const rosePine: ThemeDefinition = {
  name: "rose-pine",
  displayName: "Ros\u00e9 Pine",
  modes: ["dark", "light"],
  colors: {
    // ── Core UI ──────────────────────────────────────────────
    primary: {
      dark: RGBA.fromHex("#c4a7e7"), // iris (main)
      light: RGBA.fromHex("#907aa9"), // iris (dawn)
    },
    secondary: {
      dark: RGBA.fromHex("#ebbcba"), // rose (main)
      light: RGBA.fromHex("#d7827e"), // rose (dawn)
    },
    accent: {
      dark: RGBA.fromHex("#f6c177"), // gold (main)
      light: RGBA.fromHex("#ea9d34"), // gold (dawn)
    },

    // ── Text ─────────────────────────────────────────────────
    text: {
      dark: RGBA.fromHex("#e0def4"), // text (main)
      light: RGBA.fromHex("#575279"), // text (dawn)
    },
    textMuted: {
      dark: RGBA.fromHex("#6e6a86"), // muted (main)
      light: RGBA.fromHex("#9893a5"), // muted (dawn)
    },

    // ── Backgrounds ──────────────────────────────────────────
    background: {
      dark: RGBA.fromHex("#191724"), // base (main)
      light: RGBA.fromHex("#faf4ed"), // base (dawn)
    },
    backgroundPanel: {
      dark: RGBA.fromHex("#1f1d2e"), // surface (main)
      light: RGBA.fromHex("#fffaf3"), // surface (dawn)
    },
    backgroundElement: {
      dark: RGBA.fromHex("#26233a"), // overlay (main)
      light: RGBA.fromHex("#f2e9e1"), // overlay (dawn)
    },
    backgroundOverlay: {
      dark: RGBA.fromInts(0, 0, 0, 200),
      light: RGBA.fromInts(0, 0, 0, 180),
    },
    backgroundSelected: {
      dark: RGBA.fromHex("#2a283e"),
      light: RGBA.fromHex("#eee8e0"),
    },

    // ── Borders ──────────────────────────────────────────────
    border: {
      dark: RGBA.fromHex("#403d52"), // highlight med (main)
      light: RGBA.fromHex("#dfdad9"), // highlight med (dawn)
    },
    borderActive: {
      dark: RGBA.fromHex("#c4a7e7"), // iris
      light: RGBA.fromHex("#907aa9"),
    },
    borderSubtle: {
      dark: RGBA.fromHex("#26233a"), // overlay
      light: RGBA.fromHex("#f2e9e1"),
    },

    // ── Semantic Status ──────────────────────────────────────
    error: {
      dark: RGBA.fromHex("#eb6f92"), // love (main)
      light: RGBA.fromHex("#b4637a"), // love (dawn)
    },
    warning: {
      dark: RGBA.fromHex("#f6c177"), // gold (main)
      light: RGBA.fromHex("#ea9d34"), // gold (dawn)
    },
    success: {
      dark: RGBA.fromHex("#9ccfd8"), // foam (main) — used as success/green
      light: RGBA.fromHex("#56949f"), // foam (dawn)
    },
    info: {
      dark: RGBA.fromHex("#c4a7e7"), // iris (main)
      light: RGBA.fromHex("#907aa9"), // iris (dawn)
    },

    // ── Permission Tiers ─────────────────────────────────────
    tierSafe: {
      dark: RGBA.fromHex("#9ccfd8"), // foam
      light: RGBA.fromHex("#56949f"),
    },
    tierModerate: {
      dark: RGBA.fromHex("#f6c177"), // gold
      light: RGBA.fromHex("#ea9d34"),
    },
    tierRisky: {
      dark: RGBA.fromHex("#ebbcba"), // rose
      light: RGBA.fromHex("#d7827e"),
    },
    tierDangerous: {
      dark: RGBA.fromHex("#eb6f92"), // love
      light: RGBA.fromHex("#b4637a"),
    },

    // ── Markdown Rendering ───────────────────────────────────
    markdownCode: {
      dark: RGBA.fromHex("#9ccfd8"), // foam
      light: RGBA.fromHex("#56949f"),
    },
    markdownLink: {
      dark: RGBA.fromHex("#c4a7e7"), // iris
      light: RGBA.fromHex("#907aa9"),
    },
    markdownHeading: {
      dark: RGBA.fromHex("#ebbcba"), // rose
      light: RGBA.fromHex("#d7827e"),
    },
    markdownStrong: {
      dark: RGBA.fromHex("#f6c177"), // gold
      light: RGBA.fromHex("#ea9d34"),
    },
    markdownEmph: {
      dark: RGBA.fromHex("#eb6f92"), // love
      light: RGBA.fromHex("#b4637a"),
    },

    // ── Diff ─────────────────────────────────────────────────
    diffAdded: {
      dark: RGBA.fromHex("#9ccfd8"), // foam
      light: RGBA.fromHex("#56949f"),
    },
    diffRemoved: {
      dark: RGBA.fromHex("#eb6f92"), // love
      light: RGBA.fromHex("#b4637a"),
    },
    diffAddedBg: {
      dark: RGBA.fromHex("#1a2b2e"),
      light: RGBA.fromHex("#ddeae6"),
    },
    diffRemovedBg: {
      dark: RGBA.fromHex("#2e1a24"),
      light: RGBA.fromHex("#f5dce1"),
    },
  },
};
