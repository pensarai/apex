/**
 * Monokai — Dark: Classic Monokai Pro, Light: Designed
 *
 * Dark sourced from Monokai Pro (https://monokai.pro)
 * Light variant designed to preserve Monokai's vivid accent identity.
 */

import { RGBA } from "@opentui/core";
import type { ThemeDefinition } from "../types";

export const monokai: ThemeDefinition = {
  name: "monokai",
  displayName: "Monokai",
  modes: ["dark", "light"],
  colors: {
    // ── Core UI ──────────────────────────────────────────────
    primary: {
      dark: RGBA.fromHex("#a9dc76"), // green
      light: RGBA.fromHex("#4d7a27"),
    },
    secondary: {
      dark: RGBA.fromHex("#78dce8"), // cyan
      light: RGBA.fromHex("#0b7e8b"),
    },
    accent: {
      dark: RGBA.fromHex("#ab9df2"), // purple
      light: RGBA.fromHex("#6e56cf"),
    },

    // ── Text ─────────────────────────────────────────────────
    text: {
      dark: RGBA.fromHex("#fcfcfa"), // fg
      light: RGBA.fromHex("#2c292d"),
    },
    textMuted: {
      dark: RGBA.fromHex("#727072"), // comment
      light: RGBA.fromHex("#9e9b9f"),
    },

    // ── Backgrounds ──────────────────────────────────────────
    background: {
      dark: RGBA.fromHex("#2d2a2e"), // bg
      light: RGBA.fromHex("#fafaf8"),
    },
    backgroundPanel: {
      dark: RGBA.fromHex("#221f22"),
      light: RGBA.fromHex("#f0f0ee"),
    },
    backgroundElement: {
      dark: RGBA.fromHex("#403e41"),
      light: RGBA.fromHex("#e8e8e6"),
    },
    backgroundOverlay: {
      dark: RGBA.fromInts(0, 0, 0, 200),
      light: RGBA.fromInts(255, 255, 255, 200),
    },
    backgroundSelected: {
      dark: RGBA.fromHex("#4a474c"),
      light: RGBA.fromHex("#dddcda"),
    },

    // ── Borders ──────────────────────────────────────────────
    border: {
      dark: RGBA.fromHex("#5b595c"),
      light: RGBA.fromHex("#c8c7c5"),
    },
    borderActive: {
      dark: RGBA.fromHex("#a9dc76"),
      light: RGBA.fromHex("#4d7a27"),
    },
    borderSubtle: {
      dark: RGBA.fromHex("#403e41"),
      light: RGBA.fromHex("#e8e8e6"),
    },

    // ── Semantic Status ──────────────────────────────────────
    error: {
      dark: RGBA.fromHex("#ff6188"), // red/pink
      light: RGBA.fromHex("#cc2944"),
    },
    warning: {
      dark: RGBA.fromHex("#ffd866"), // yellow
      light: RGBA.fromHex("#a67f00"),
    },
    success: {
      dark: RGBA.fromHex("#a9dc76"), // green
      light: RGBA.fromHex("#4d7a27"),
    },
    info: {
      dark: RGBA.fromHex("#78dce8"), // cyan
      light: RGBA.fromHex("#0b7e8b"),
    },

    // ── Permission Tiers ─────────────────────────────────────
    tierSafe: {
      dark: RGBA.fromHex("#a9dc76"),
      light: RGBA.fromHex("#4d7a27"),
    },
    tierModerate: {
      dark: RGBA.fromHex("#ffd866"),
      light: RGBA.fromHex("#a67f00"),
    },
    tierRisky: {
      dark: RGBA.fromHex("#fc9867"), // orange
      light: RGBA.fromHex("#c25d00"),
    },
    tierDangerous: {
      dark: RGBA.fromHex("#ff6188"),
      light: RGBA.fromHex("#cc2944"),
    },

    // ── Markdown Rendering ───────────────────────────────────
    markdownCode: {
      dark: RGBA.fromHex("#a9dc76"),
      light: RGBA.fromHex("#4d7a27"),
    },
    markdownLink: {
      dark: RGBA.fromHex("#78dce8"),
      light: RGBA.fromHex("#0b7e8b"),
    },
    markdownHeading: {
      dark: RGBA.fromHex("#ff6188"),
      light: RGBA.fromHex("#cc2944"),
    },
    markdownStrong: {
      dark: RGBA.fromHex("#fc9867"),
      light: RGBA.fromHex("#c25d00"),
    },
    markdownEmph: {
      dark: RGBA.fromHex("#ffd866"),
      light: RGBA.fromHex("#a67f00"),
    },

    // ── Diff ─────────────────────────────────────────────────
    diffAdded: {
      dark: RGBA.fromHex("#a9dc76"),
      light: RGBA.fromHex("#4d7a27"),
    },
    diffRemoved: {
      dark: RGBA.fromHex("#ff6188"),
      light: RGBA.fromHex("#cc2944"),
    },
    diffAddedBg: {
      dark: RGBA.fromHex("#243425"),
      light: RGBA.fromHex("#d8edcf"),
    },
    diffRemovedBg: {
      dark: RGBA.fromHex("#3a1a24"),
      light: RGBA.fromHex("#f8d5d8"),
    },
  },
};
