/**
 * Nord — Dark: Polar Night, Light: Snow Storm
 *
 * Sourced from https://www.nordtheme.com
 * nord0-3: Polar Night, nord4-6: Snow Storm, nord7-10: Frost, nord11-15: Aurora
 */

import { RGBA } from "@opentui/core";
import type { ThemeDefinition } from "../types";

export const nord: ThemeDefinition = {
  name: "nord",
  displayName: "Nord",
  modes: ["dark", "light"],
  colors: {
    // ── Core UI ──────────────────────────────────────────────
    primary: {
      dark: RGBA.fromHex("#88c0d0"), // nord8 (frost cyan)
      light: RGBA.fromHex("#5e81ac"), // nord10 (frost dark blue)
    },
    secondary: {
      dark: RGBA.fromHex("#81a1c1"), // nord9 (frost blue)
      light: RGBA.fromHex("#81a1c1"), // nord9
    },
    accent: {
      dark: RGBA.fromHex("#5e81ac"), // nord10 (frost dark blue)
      light: RGBA.fromHex("#88c0d0"), // nord8
    },

    // ── Text ─────────────────────────────────────────────────
    text: {
      dark: RGBA.fromHex("#eceff4"), // nord6 (snow storm brightest)
      light: RGBA.fromHex("#2e3440"), // nord0 (polar night darkest)
    },
    textMuted: {
      dark: RGBA.fromHex("#4c566a"), // nord3 (polar night lightest)
      light: RGBA.fromHex("#7b88a1"),
    },

    // ── Backgrounds ──────────────────────────────────────────
    background: {
      dark: RGBA.fromHex("#2e3440"), // nord0
      light: RGBA.fromHex("#eceff4"), // nord6
    },
    backgroundPanel: {
      dark: RGBA.fromHex("#272c36"),
      light: RGBA.fromHex("#e5e9f0"), // nord5
    },
    backgroundElement: {
      dark: RGBA.fromHex("#3b4252"), // nord1
      light: RGBA.fromHex("#d8dee9"), // nord4
    },
    backgroundOverlay: {
      dark: RGBA.fromInts(0, 0, 0, 200),
      light: RGBA.fromInts(0, 0, 0, 180),
    },
    backgroundSelected: {
      dark: RGBA.fromHex("#434c5e"), // nord2
      light: RGBA.fromHex("#d0d6e1"),
    },

    // ── Borders ──────────────────────────────────────────────
    border: {
      dark: RGBA.fromHex("#4c566a"), // nord3
      light: RGBA.fromHex("#c3cad5"),
    },
    borderActive: {
      dark: RGBA.fromHex("#88c0d0"), // nord8
      light: RGBA.fromHex("#5e81ac"), // nord10
    },
    borderSubtle: {
      dark: RGBA.fromHex("#3b4252"), // nord1
      light: RGBA.fromHex("#d8dee9"), // nord4
    },

    // ── Semantic Status ──────────────────────────────────────
    error: {
      dark: RGBA.fromHex("#bf616a"), // nord11 (aurora red)
      light: RGBA.fromHex("#bf616a"),
    },
    warning: {
      dark: RGBA.fromHex("#ebcb8b"), // nord13 (aurora yellow)
      light: RGBA.fromHex("#c08b30"),
    },
    success: {
      dark: RGBA.fromHex("#a3be8c"), // nord14 (aurora green)
      light: RGBA.fromHex("#6d8a54"),
    },
    info: {
      dark: RGBA.fromHex("#88c0d0"), // nord8 (frost cyan)
      light: RGBA.fromHex("#5e81ac"), // nord10
    },

    // ── Permission Tiers ─────────────────────────────────────
    tierSafe: {
      dark: RGBA.fromHex("#a3be8c"), // nord14
      light: RGBA.fromHex("#6d8a54"),
    },
    tierModerate: {
      dark: RGBA.fromHex("#ebcb8b"), // nord13
      light: RGBA.fromHex("#c08b30"),
    },
    tierRisky: {
      dark: RGBA.fromHex("#d08770"), // nord12 (aurora orange)
      light: RGBA.fromHex("#c46840"),
    },
    tierDangerous: {
      dark: RGBA.fromHex("#bf616a"), // nord11
      light: RGBA.fromHex("#bf616a"),
    },

    // ── Markdown Rendering ───────────────────────────────────
    markdownCode: {
      dark: RGBA.fromHex("#a3be8c"), // nord14
      light: RGBA.fromHex("#6d8a54"),
    },
    markdownLink: {
      dark: RGBA.fromHex("#88c0d0"), // nord8
      light: RGBA.fromHex("#5e81ac"),
    },
    markdownHeading: {
      dark: RGBA.fromHex("#81a1c1"), // nord9
      light: RGBA.fromHex("#5e81ac"),
    },
    markdownStrong: {
      dark: RGBA.fromHex("#d08770"), // nord12
      light: RGBA.fromHex("#c46840"),
    },
    markdownEmph: {
      dark: RGBA.fromHex("#ebcb8b"), // nord13
      light: RGBA.fromHex("#c08b30"),
    },

    // ── Diff ─────────────────────────────────────────────────
    diffAdded: {
      dark: RGBA.fromHex("#a3be8c"), // nord14
      light: RGBA.fromHex("#6d8a54"),
    },
    diffRemoved: {
      dark: RGBA.fromHex("#bf616a"), // nord11
      light: RGBA.fromHex("#bf616a"),
    },
    diffAddedBg: {
      dark: RGBA.fromHex("#2b3328"),
      light: RGBA.fromHex("#dde8d2"),
    },
    diffRemovedBg: {
      dark: RGBA.fromHex("#3b2a2c"),
      light: RGBA.fromHex("#ebd5d7"),
    },
  },
};
