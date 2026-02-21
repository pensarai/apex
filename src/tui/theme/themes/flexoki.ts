/**
 * Flexoki — Dark: Flexoki Dark, Light: Flexoki Light
 *
 * Sourced from https://github.com/kepano/flexoki
 * An inky color scheme designed for reading and writing.
 */

import { RGBA } from "@opentui/core";
import type { ThemeDefinition } from "../types";

export const flexoki: ThemeDefinition = {
  name: "flexoki",
  displayName: "Flexoki",
  modes: ["dark", "light"],
  colors: {
    // ── Core UI ──────────────────────────────────────────────
    primary: {
      dark: RGBA.fromHex("#879a39"), // green
      light: RGBA.fromHex("#66800b"),
    },
    secondary: {
      dark: RGBA.fromHex("#4385be"), // blue
      light: RGBA.fromHex("#205ea6"),
    },
    accent: {
      dark: RGBA.fromHex("#a580e2"), // purple
      light: RGBA.fromHex("#8b7ec8"),
    },

    // ── Text ─────────────────────────────────────────────────
    text: {
      dark: RGBA.fromHex("#cecdc3"), // tx
      light: RGBA.fromHex("#100f0f"), // tx
    },
    textMuted: {
      dark: RGBA.fromHex("#878580"), // tx-2
      light: RGBA.fromHex("#6f6e69"), // tx-2
    },

    // ── Backgrounds ──────────────────────────────────────────
    background: {
      dark: RGBA.fromHex("#100f0f"), // bg
      light: RGBA.fromHex("#fffcf0"), // bg
    },
    backgroundPanel: {
      dark: RGBA.fromHex("#1c1b1a"), // bg-2
      light: RGBA.fromHex("#f2f0e5"), // bg-2
    },
    backgroundElement: {
      dark: RGBA.fromHex("#282726"), // ui
      light: RGBA.fromHex("#e6e4d9"), // ui
    },
    backgroundOverlay: {
      dark: RGBA.fromInts(0, 0, 0, 200),
      light: RGBA.fromInts(255, 255, 255, 200),
    },
    backgroundSelected: {
      dark: RGBA.fromHex("#343331"), // ui-2
      light: RGBA.fromHex("#dad8ce"), // ui-2
    },

    // ── Borders ──────────────────────────────────────────────
    border: {
      dark: RGBA.fromHex("#403e3c"), // ui-3
      light: RGBA.fromHex("#cecdc3"), // ui-3
    },
    borderActive: {
      dark: RGBA.fromHex("#879a39"),
      light: RGBA.fromHex("#66800b"),
    },
    borderSubtle: {
      dark: RGBA.fromHex("#282726"),
      light: RGBA.fromHex("#e6e4d9"),
    },

    // ── Semantic Status ──────────────────────────────────────
    error: {
      dark: RGBA.fromHex("#d14d41"), // red
      light: RGBA.fromHex("#af3029"),
    },
    warning: {
      dark: RGBA.fromHex("#d0a215"), // yellow
      light: RGBA.fromHex("#ad8301"),
    },
    success: {
      dark: RGBA.fromHex("#879a39"), // green
      light: RGBA.fromHex("#66800b"),
    },
    info: {
      dark: RGBA.fromHex("#4385be"), // blue
      light: RGBA.fromHex("#205ea6"),
    },

    // ── Permission Tiers ─────────────────────────────────────
    tierSafe: {
      dark: RGBA.fromHex("#879a39"),
      light: RGBA.fromHex("#66800b"),
    },
    tierModerate: {
      dark: RGBA.fromHex("#d0a215"),
      light: RGBA.fromHex("#ad8301"),
    },
    tierRisky: {
      dark: RGBA.fromHex("#da702c"), // orange
      light: RGBA.fromHex("#bc5215"),
    },
    tierDangerous: {
      dark: RGBA.fromHex("#d14d41"),
      light: RGBA.fromHex("#af3029"),
    },

    // ── Markdown Rendering ───────────────────────────────────
    markdownCode: {
      dark: RGBA.fromHex("#879a39"),
      light: RGBA.fromHex("#66800b"),
    },
    markdownLink: {
      dark: RGBA.fromHex("#4385be"),
      light: RGBA.fromHex("#205ea6"),
    },
    markdownHeading: {
      dark: RGBA.fromHex("#da702c"),
      light: RGBA.fromHex("#bc5215"),
    },
    markdownStrong: {
      dark: RGBA.fromHex("#d0a215"),
      light: RGBA.fromHex("#ad8301"),
    },
    markdownEmph: {
      dark: RGBA.fromHex("#a580e2"),
      light: RGBA.fromHex("#8b7ec8"),
    },

    // ── Diff ─────────────────────────────────────────────────
    diffAdded: {
      dark: RGBA.fromHex("#879a39"),
      light: RGBA.fromHex("#66800b"),
    },
    diffRemoved: {
      dark: RGBA.fromHex("#d14d41"),
      light: RGBA.fromHex("#af3029"),
    },
    diffAddedBg: {
      dark: RGBA.fromHex("#1a2418"),
      light: RGBA.fromHex("#e0e8c8"),
    },
    diffRemovedBg: {
      dark: RGBA.fromHex("#2a1818"),
      light: RGBA.fromHex("#f5d5d0"),
    },
  },
};
