/**
 * Vesper — Dark: Canonical, Light: Designed
 *
 * Dark sourced from https://github.com/raunofreiberg/vesper
 * A warm, dark theme with orange/amber accents.
 * Light variant designed to preserve Vesper's warm amber identity.
 */

import { RGBA } from "@opentui/core";
import type { ThemeDefinition } from "../types";

export const vesper: ThemeDefinition = {
  name: "vesper",
  displayName: "Vesper",
  modes: ["dark", "light"],
  colors: {
    // ── Core UI ──────────────────────────────────────────────
    primary: {
      dark: RGBA.fromHex("#ffc799"), // orange/amber accent
      light: RGBA.fromHex("#b35c00"),
    },
    secondary: {
      dark: RGBA.fromHex("#99ffe4"), // teal/mint
      light: RGBA.fromHex("#007a5e"),
    },
    accent: {
      dark: RGBA.fromHex("#d4a0ff"), // purple
      light: RGBA.fromHex("#7e3aaf"),
    },

    // ── Text ─────────────────────────────────────────────────
    text: {
      dark: RGBA.fromHex("#d4d4d4"), // fg
      light: RGBA.fromHex("#1c1c1c"),
    },
    textMuted: {
      dark: RGBA.fromHex("#505050"), // comment
      light: RGBA.fromHex("#999999"),
    },

    // ── Backgrounds ──────────────────────────────────────────
    background: {
      dark: RGBA.fromHex("#101010"), // bg
      light: RGBA.fromHex("#faf8f5"),
    },
    backgroundPanel: {
      dark: RGBA.fromHex("#0a0a0a"),
      light: RGBA.fromHex("#f0eee8"),
    },
    backgroundElement: {
      dark: RGBA.fromHex("#1a1a1a"),
      light: RGBA.fromHex("#e8e6e0"),
    },
    backgroundOverlay: {
      dark: RGBA.fromInts(0, 0, 0, 200),
      light: RGBA.fromInts(255, 255, 255, 200),
    },
    backgroundSelected: {
      dark: RGBA.fromHex("#232323"),
      light: RGBA.fromHex("#dddbd5"),
    },

    // ── Borders ──────────────────────────────────────────────
    border: {
      dark: RGBA.fromHex("#2a2a2a"),
      light: RGBA.fromHex("#d0cec8"),
    },
    borderActive: {
      dark: RGBA.fromHex("#ffc799"),
      light: RGBA.fromHex("#b35c00"),
    },
    borderSubtle: {
      dark: RGBA.fromHex("#1a1a1a"),
      light: RGBA.fromHex("#e8e6e0"),
    },

    // ── Semantic Status ──────────────────────────────────────
    error: {
      dark: RGBA.fromHex("#f14c4c"), // red
      light: RGBA.fromHex("#c62828"),
    },
    warning: {
      dark: RGBA.fromHex("#ffc799"), // amber
      light: RGBA.fromHex("#b35c00"),
    },
    success: {
      dark: RGBA.fromHex("#99ffe4"), // teal
      light: RGBA.fromHex("#007a5e"),
    },
    info: {
      dark: RGBA.fromHex("#a0c4ff"), // blue
      light: RGBA.fromHex("#2563a0"),
    },

    // ── Permission Tiers ─────────────────────────────────────
    tierSafe: {
      dark: RGBA.fromHex("#99ffe4"),
      light: RGBA.fromHex("#007a5e"),
    },
    tierModerate: {
      dark: RGBA.fromHex("#ffc799"),
      light: RGBA.fromHex("#b35c00"),
    },
    tierRisky: {
      dark: RGBA.fromHex("#ff9e64"),
      light: RGBA.fromHex("#c25d00"),
    },
    tierDangerous: {
      dark: RGBA.fromHex("#f14c4c"),
      light: RGBA.fromHex("#c62828"),
    },

    // ── Markdown Rendering ───────────────────────────────────
    markdownCode: {
      dark: RGBA.fromHex("#99ffe4"),
      light: RGBA.fromHex("#007a5e"),
    },
    markdownLink: {
      dark: RGBA.fromHex("#a0c4ff"),
      light: RGBA.fromHex("#2563a0"),
    },
    markdownHeading: {
      dark: RGBA.fromHex("#ffc799"),
      light: RGBA.fromHex("#b35c00"),
    },
    markdownStrong: {
      dark: RGBA.fromHex("#d4a0ff"),
      light: RGBA.fromHex("#7e3aaf"),
    },
    markdownEmph: {
      dark: RGBA.fromHex("#ffcb6b"),
      light: RGBA.fromHex("#a67f00"),
    },

    // ── Diff ─────────────────────────────────────────────────
    diffAdded: {
      dark: RGBA.fromHex("#99ffe4"),
      light: RGBA.fromHex("#007a5e"),
    },
    diffRemoved: {
      dark: RGBA.fromHex("#f14c4c"),
      light: RGBA.fromHex("#c62828"),
    },
    diffAddedBg: {
      dark: RGBA.fromHex("#0d2620"),
      light: RGBA.fromHex("#d5ede5"),
    },
    diffRemovedBg: {
      dark: RGBA.fromHex("#2e1414"),
      light: RGBA.fromHex("#f5d5d5"),
    },
  },
};
