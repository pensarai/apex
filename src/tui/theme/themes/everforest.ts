/**
 * Everforest — Dark: Everforest Dark, Light: Everforest Light
 *
 * Sourced from https://github.com/sainnhe/everforest
 */

import { RGBA } from "@opentui/core";
import type { ThemeDefinition } from "../types";

export const everforest: ThemeDefinition = {
  name: "everforest",
  displayName: "Everforest",
  modes: ["dark", "light"],
  colors: {
    // ── Core UI ──────────────────────────────────────────────
    primary: {
      dark: RGBA.fromHex("#a7c080"), // green
      light: RGBA.fromHex("#8da101"), // green
    },
    secondary: {
      dark: RGBA.fromHex("#7fbbb3"), // aqua
      light: RGBA.fromHex("#35a77c"), // aqua
    },
    accent: {
      dark: RGBA.fromHex("#d699b6"), // purple
      light: RGBA.fromHex("#df69ba"), // purple
    },

    // ── Text ─────────────────────────────────────────────────
    text: {
      dark: RGBA.fromHex("#d3c6aa"), // fg
      light: RGBA.fromHex("#5c6a72"), // fg
    },
    textMuted: {
      dark: RGBA.fromHex("#859289"), // grey1
      light: RGBA.fromHex("#939f91"), // grey0
    },

    // ── Backgrounds ──────────────────────────────────────────
    background: {
      dark: RGBA.fromHex("#2d353b"), // bg0 (medium)
      light: RGBA.fromHex("#fdf6e3"), // bg0 (medium)
    },
    backgroundPanel: {
      dark: RGBA.fromHex("#272e33"), // bg_dim
      light: RGBA.fromHex("#f3ead3"), // bg_dim
    },
    backgroundElement: {
      dark: RGBA.fromHex("#343f44"), // bg1
      light: RGBA.fromHex("#efebd4"), // bg1
    },
    backgroundOverlay: {
      dark: RGBA.fromInts(0, 0, 0, 200),
      light: RGBA.fromInts(255, 255, 255, 200),
    },
    backgroundSelected: {
      dark: RGBA.fromHex("#3d484d"), // bg2
      light: RGBA.fromHex("#e6e2cc"), // bg2
    },

    // ── Borders ──────────────────────────────────────────────
    border: {
      dark: RGBA.fromHex("#4f585e"), // bg4
      light: RGBA.fromHex("#d4d0ba"),
    },
    borderActive: {
      dark: RGBA.fromHex("#a7c080"), // green
      light: RGBA.fromHex("#8da101"),
    },
    borderSubtle: {
      dark: RGBA.fromHex("#343f44"), // bg1
      light: RGBA.fromHex("#efebd4"),
    },

    // ── Semantic Status ──────────────────────────────────────
    error: {
      dark: RGBA.fromHex("#e67e80"), // red
      light: RGBA.fromHex("#f85552"), // red
    },
    warning: {
      dark: RGBA.fromHex("#dbbc7f"), // yellow
      light: RGBA.fromHex("#dfa000"), // yellow
    },
    success: {
      dark: RGBA.fromHex("#a7c080"), // green
      light: RGBA.fromHex("#8da101"), // green
    },
    info: {
      dark: RGBA.fromHex("#7fbbb3"), // aqua
      light: RGBA.fromHex("#35a77c"), // aqua
    },

    // ── Permission Tiers ─────────────────────────────────────
    tierSafe: {
      dark: RGBA.fromHex("#a7c080"),
      light: RGBA.fromHex("#8da101"),
    },
    tierModerate: {
      dark: RGBA.fromHex("#dbbc7f"),
      light: RGBA.fromHex("#dfa000"),
    },
    tierRisky: {
      dark: RGBA.fromHex("#e69875"), // orange
      light: RGBA.fromHex("#f57d26"), // orange
    },
    tierDangerous: {
      dark: RGBA.fromHex("#e67e80"),
      light: RGBA.fromHex("#f85552"),
    },

    // ── Markdown Rendering ───────────────────────────────────
    markdownCode: {
      dark: RGBA.fromHex("#a7c080"),
      light: RGBA.fromHex("#8da101"),
    },
    markdownLink: {
      dark: RGBA.fromHex("#7fbbb3"),
      light: RGBA.fromHex("#35a77c"),
    },
    markdownHeading: {
      dark: RGBA.fromHex("#e69875"), // orange
      light: RGBA.fromHex("#f57d26"),
    },
    markdownStrong: {
      dark: RGBA.fromHex("#dbbc7f"),
      light: RGBA.fromHex("#dfa000"),
    },
    markdownEmph: {
      dark: RGBA.fromHex("#d699b6"),
      light: RGBA.fromHex("#df69ba"),
    },

    // ── Diff ─────────────────────────────────────────────────
    diffAdded: {
      dark: RGBA.fromHex("#a7c080"),
      light: RGBA.fromHex("#8da101"),
    },
    diffRemoved: {
      dark: RGBA.fromHex("#e67e80"),
      light: RGBA.fromHex("#f85552"),
    },
    diffAddedBg: {
      dark: RGBA.fromHex("#283428"),
      light: RGBA.fromHex("#dfe8c8"),
    },
    diffRemovedBg: {
      dark: RGBA.fromHex("#3a2424"),
      light: RGBA.fromHex("#f5d5d0"),
    },
  },
};
