/**
 * Nightfox — Dark: Nightfox, Light: Dayfox
 *
 * Sourced from https://github.com/EdenEast/nightfox.nvim
 */

import { RGBA } from "@opentui/core";
import type { ThemeDefinition } from "../types";

export const nightfox: ThemeDefinition = {
  name: "nightfox",
  displayName: "Nightfox",
  modes: ["dark", "light"],
  colors: {
    // ── Core UI ──────────────────────────────────────────────
    primary: {
      dark: RGBA.fromHex("#719cd6"), // blue
      light: RGBA.fromHex("#2848a9"), // blue (dayfox)
    },
    secondary: {
      dark: RGBA.fromHex("#9d79d6"), // magenta
      light: RGBA.fromHex("#6e33ce"), // magenta (dayfox)
    },
    accent: {
      dark: RGBA.fromHex("#f4a261"), // orange
      light: RGBA.fromHex("#955f61"), // orange (dayfox)
    },

    // ── Text ─────────────────────────────────────────────────
    text: {
      dark: RGBA.fromHex("#cdcecf"), // fg1
      light: RGBA.fromHex("#3d2b5a"), // fg1 (dayfox)
    },
    textMuted: {
      dark: RGBA.fromHex("#738091"), // comment
      light: RGBA.fromHex("#837a72"), // comment (dayfox)
    },

    // ── Backgrounds ──────────────────────────────────────────
    background: {
      dark: RGBA.fromHex("#192330"), // bg
      light: RGBA.fromHex("#f6f2ee"),
    },
    backgroundPanel: {
      dark: RGBA.fromHex("#131a24"), // bg0
      light: RGBA.fromHex("#e4dcd4"), // bg0 (dayfox)
    },
    backgroundElement: {
      dark: RGBA.fromHex("#212e3f"), // bg2
      light: RGBA.fromHex("#d3c7bb"), // bg3 (dayfox)
    },
    backgroundOverlay: {
      dark: RGBA.fromInts(0, 0, 0, 200),
      light: RGBA.fromInts(255, 255, 255, 200),
    },
    backgroundSelected: {
      dark: RGBA.fromHex("#2b3b51"), // sel0
      light: RGBA.fromHex("#e7d2be"), // sel0 (dayfox)
    },

    // ── Borders ──────────────────────────────────────────────
    border: {
      dark: RGBA.fromHex("#39506d"), // bg4
      light: RGBA.fromHex("#aab0ad"), // bg4 (dayfox)
    },
    borderActive: {
      dark: RGBA.fromHex("#719cd6"),
      light: RGBA.fromHex("#2848a9"),
    },
    borderSubtle: {
      dark: RGBA.fromHex("#212e3f"),
      light: RGBA.fromHex("#d3c7bb"), // bg3 (dayfox)
    },

    // ── Semantic Status ──────────────────────────────────────
    error: {
      dark: RGBA.fromHex("#c94f6d"), // red
      light: RGBA.fromHex("#a5222f"), // red (dayfox)
    },
    warning: {
      dark: RGBA.fromHex("#dbc074"), // yellow
      light: RGBA.fromHex("#AC5402"), // yellow (dayfox)
    },
    success: {
      dark: RGBA.fromHex("#81b29a"), // green
      light: RGBA.fromHex("#396847"), // green (dayfox)
    },
    info: {
      dark: RGBA.fromHex("#63cdcf"), // cyan
      light: RGBA.fromHex("#287980"), // cyan (dayfox)
    },

    // ── Permission Tiers ─────────────────────────────────────
    tierSafe: {
      dark: RGBA.fromHex("#81b29a"),
      light: RGBA.fromHex("#396847"),
    },
    tierModerate: {
      dark: RGBA.fromHex("#dbc074"),
      light: RGBA.fromHex("#AC5402"),
    },
    tierRisky: {
      dark: RGBA.fromHex("#f4a261"),
      light: RGBA.fromHex("#955f61"),
    },
    tierDangerous: {
      dark: RGBA.fromHex("#c94f6d"),
      light: RGBA.fromHex("#a5222f"),
    },

    // ── Markdown Rendering ───────────────────────────────────
    markdownCode: {
      dark: RGBA.fromHex("#81b29a"),
      light: RGBA.fromHex("#396847"),
    },
    markdownLink: {
      dark: RGBA.fromHex("#63cdcf"),
      light: RGBA.fromHex("#287980"),
    },
    markdownHeading: {
      dark: RGBA.fromHex("#9d79d6"),
      light: RGBA.fromHex("#6e33ce"),
    },
    markdownStrong: {
      dark: RGBA.fromHex("#f4a261"),
      light: RGBA.fromHex("#955f61"),
    },
    markdownEmph: {
      dark: RGBA.fromHex("#dbc074"),
      light: RGBA.fromHex("#AC5402"),
    },

    // ── Diff ─────────────────────────────────────────────────
    diffAdded: {
      dark: RGBA.fromHex("#81b29a"),
      light: RGBA.fromHex("#396847"),
    },
    diffRemoved: {
      dark: RGBA.fromHex("#c94f6d"),
      light: RGBA.fromHex("#a5222f"),
    },
    diffAddedBg: {
      dark: RGBA.fromHex("#1a2e28"),
      light: RGBA.fromHex("#d5e8d8"),
    },
    diffRemovedBg: {
      dark: RGBA.fromHex("#2e1a22"),
      light: RGBA.fromHex("#f5d5d8"),
    },
  },
};
