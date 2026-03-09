/**
 * Gruvbox — Dark: Gruvbox Dark, Light: Gruvbox Light
 *
 * Sourced from https://github.com/morhetz/gruvbox
 */

import { RGBA } from "@opentui/core";
import type { ThemeDefinition } from "../types";

export const gruvbox: ThemeDefinition = {
  name: "gruvbox",
  displayName: "Gruvbox",
  modes: ["dark", "light"],
  colors: {
    // ── Core UI ──────────────────────────────────────────────
    primary: {
      dark: RGBA.fromHex("#fe8019"), // orange (bright)
      light: RGBA.fromHex("#af3a03"), // orange (faded)
    },
    secondary: {
      dark: RGBA.fromHex("#83a598"), // aqua
      light: RGBA.fromHex("#427b58"), // aqua (faded)
    },
    accent: {
      dark: RGBA.fromHex("#d3869b"), // purple
      light: RGBA.fromHex("#8f3f71"), // purple (faded)
    },

    // ── Text ─────────────────────────────────────────────────
    text: {
      dark: RGBA.fromHex("#ebdbb2"), // fg (light0)
      light: RGBA.fromHex("#3c3836"), // fg (dark1)
    },
    textMuted: {
      dark: RGBA.fromHex("#928374"), // gray
      light: RGBA.fromHex("#928374"), // gray
    },

    // ── Backgrounds ──────────────────────────────────────────
    background: {
      dark: RGBA.fromHex("#282828"), // bg (dark0)
      light: RGBA.fromHex("#fbf1c7"), // bg (light0)
    },
    backgroundPanel: {
      dark: RGBA.fromHex("#1d2021"), // bg0_h
      light: RGBA.fromHex("#f9f5d7"), // bg0_h (light)
    },
    backgroundElement: {
      dark: RGBA.fromHex("#3c3836"), // bg1 (dark1)
      light: RGBA.fromHex("#ebdbb2"), // bg1 (light1)
    },
    backgroundOverlay: {
      dark: RGBA.fromInts(0, 0, 0, 200),
      light: RGBA.fromInts(0, 0, 0, 180),
    },
    backgroundSelected: {
      dark: RGBA.fromHex("#504945"), // bg2 (dark2)
      light: RGBA.fromHex("#d5c4a1"), // bg2 (light2)
    },

    // ── Borders ──────────────────────────────────────────────
    border: {
      dark: RGBA.fromHex("#504945"), // bg2
      light: RGBA.fromHex("#d5c4a1"), // bg2
    },
    borderActive: {
      dark: RGBA.fromHex("#fe8019"), // orange
      light: RGBA.fromHex("#af3a03"),
    },
    borderSubtle: {
      dark: RGBA.fromHex("#3c3836"), // bg1
      light: RGBA.fromHex("#ebdbb2"), // bg1
    },

    // ── Semantic Status ──────────────────────────────────────
    error: {
      dark: RGBA.fromHex("#fb4934"), // red (bright)
      light: RGBA.fromHex("#cc241d"), // red (neutral)
    },
    warning: {
      dark: RGBA.fromHex("#fabd2f"), // yellow (bright)
      light: RGBA.fromHex("#d79921"), // yellow (neutral)
    },
    success: {
      dark: RGBA.fromHex("#b8bb26"), // green (bright)
      light: RGBA.fromHex("#79740e"), // green (faded)
    },
    info: {
      dark: RGBA.fromHex("#83a598"), // aqua (bright)
      light: RGBA.fromHex("#427b58"), // aqua (faded)
    },

    // ── Permission Tiers ─────────────────────────────────────
    tierSafe: {
      dark: RGBA.fromHex("#b8bb26"),
      light: RGBA.fromHex("#79740e"),
    },
    tierModerate: {
      dark: RGBA.fromHex("#fabd2f"),
      light: RGBA.fromHex("#d79921"),
    },
    tierRisky: {
      dark: RGBA.fromHex("#fe8019"),
      light: RGBA.fromHex("#af3a03"),
    },
    tierDangerous: {
      dark: RGBA.fromHex("#fb4934"),
      light: RGBA.fromHex("#cc241d"),
    },

    // ── Markdown Rendering ───────────────────────────────────
    markdownCode: {
      dark: RGBA.fromHex("#b8bb26"), // green
      light: RGBA.fromHex("#79740e"),
    },
    markdownLink: {
      dark: RGBA.fromHex("#83a598"), // aqua
      light: RGBA.fromHex("#427b58"),
    },
    markdownHeading: {
      dark: RGBA.fromHex("#fe8019"), // orange
      light: RGBA.fromHex("#af3a03"),
    },
    markdownStrong: {
      dark: RGBA.fromHex("#fabd2f"), // yellow
      light: RGBA.fromHex("#d79921"),
    },
    markdownEmph: {
      dark: RGBA.fromHex("#d3869b"), // purple
      light: RGBA.fromHex("#8f3f71"),
    },

    // ── Diff ─────────────────────────────────────────────────
    diffAdded: {
      dark: RGBA.fromHex("#b8bb26"),
      light: RGBA.fromHex("#79740e"),
    },
    diffRemoved: {
      dark: RGBA.fromHex("#fb4934"),
      light: RGBA.fromHex("#cc241d"),
    },
    diffAddedBg: {
      dark: RGBA.fromHex("#2a331a"),
      light: RGBA.fromHex("#e4e8c8"),
    },
    diffRemovedBg: {
      dark: RGBA.fromHex("#3c1f1f"),
      light: RGBA.fromHex("#f2d5d0"),
    },
  },
};
