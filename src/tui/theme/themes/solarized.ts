/**
 * Solarized — Dark: Solarized Dark, Light: Solarized Light
 *
 * Sourced from https://ethanschoonover.com/solarized/
 */

import { RGBA } from "@opentui/core";
import type { ThemeDefinition } from "../types";

export const solarized: ThemeDefinition = {
  name: "solarized",
  displayName: "Solarized",
  modes: ["dark", "light"],
  colors: {
    // ── Core UI ──────────────────────────────────────────────
    primary: {
      dark: RGBA.fromHex("#268bd2"), // blue
      light: RGBA.fromHex("#268bd2"),
    },
    secondary: {
      dark: RGBA.fromHex("#2aa198"), // cyan
      light: RGBA.fromHex("#2aa198"),
    },
    accent: {
      dark: RGBA.fromHex("#6c71c4"), // violet
      light: RGBA.fromHex("#6c71c4"),
    },

    // ── Text ─────────────────────────────────────────────────
    text: {
      dark: RGBA.fromHex("#839496"), // base0 (body text in dark)
      light: RGBA.fromHex("#657b83"), // base00 (body text in light)
    },
    textMuted: {
      dark: RGBA.fromHex("#586e75"), // base01
      light: RGBA.fromHex("#93a1a1"), // base1
    },

    // ── Backgrounds ──────────────────────────────────────────
    background: {
      dark: RGBA.fromHex("#002b36"), // base03
      light: RGBA.fromHex("#fdf6e3"), // base3
    },
    backgroundPanel: {
      dark: RGBA.fromHex("#073642"), // base02
      light: RGBA.fromHex("#eee8d5"), // base2
    },
    backgroundElement: {
      dark: RGBA.fromHex("#094050"),
      light: RGBA.fromHex("#e4ddc8"),
    },
    backgroundOverlay: {
      dark: RGBA.fromInts(0, 0, 0, 200),
      light: RGBA.fromInts(0, 0, 0, 180),
    },
    backgroundSelected: {
      dark: RGBA.fromHex("#0a4a5c"),
      light: RGBA.fromHex("#ddd6c1"),
    },

    // ── Borders ──────────────────────────────────────────────
    border: {
      dark: RGBA.fromHex("#586e75"), // base01
      light: RGBA.fromHex("#93a1a1"), // base1
    },
    borderActive: {
      dark: RGBA.fromHex("#268bd2"), // blue
      light: RGBA.fromHex("#268bd2"),
    },
    borderSubtle: {
      dark: RGBA.fromHex("#073642"), // base02
      light: RGBA.fromHex("#eee8d5"), // base2
    },

    // ── Semantic Status ──────────────────────────────────────
    error: {
      dark: RGBA.fromHex("#dc322f"), // red
      light: RGBA.fromHex("#dc322f"),
    },
    warning: {
      dark: RGBA.fromHex("#b58900"), // yellow
      light: RGBA.fromHex("#b58900"),
    },
    success: {
      dark: RGBA.fromHex("#859900"), // green
      light: RGBA.fromHex("#859900"),
    },
    info: {
      dark: RGBA.fromHex("#2aa198"), // cyan
      light: RGBA.fromHex("#2aa198"),
    },

    // ── Permission Tiers ─────────────────────────────────────
    tierSafe: {
      dark: RGBA.fromHex("#859900"), // green
      light: RGBA.fromHex("#859900"),
    },
    tierModerate: {
      dark: RGBA.fromHex("#b58900"), // yellow
      light: RGBA.fromHex("#b58900"),
    },
    tierRisky: {
      dark: RGBA.fromHex("#cb4b16"), // orange
      light: RGBA.fromHex("#cb4b16"),
    },
    tierDangerous: {
      dark: RGBA.fromHex("#dc322f"), // red
      light: RGBA.fromHex("#dc322f"),
    },

    // ── Markdown Rendering ───────────────────────────────────
    markdownCode: {
      dark: RGBA.fromHex("#859900"), // green
      light: RGBA.fromHex("#859900"),
    },
    markdownLink: {
      dark: RGBA.fromHex("#268bd2"), // blue
      light: RGBA.fromHex("#268bd2"),
    },
    markdownHeading: {
      dark: RGBA.fromHex("#cb4b16"), // orange
      light: RGBA.fromHex("#cb4b16"),
    },
    markdownStrong: {
      dark: RGBA.fromHex("#b58900"), // yellow
      light: RGBA.fromHex("#b58900"),
    },
    markdownEmph: {
      dark: RGBA.fromHex("#6c71c4"), // violet
      light: RGBA.fromHex("#6c71c4"),
    },

    // ── Syntax Highlighting ──────────────────────────────────
    syntaxKeyword: {
      dark: RGBA.fromHex("#859900"), // green
      light: RGBA.fromHex("#738500"),
    },
    syntaxString: {
      dark: RGBA.fromHex("#2aa198"), // cyan
      light: RGBA.fromHex("#248981"),
    },
    syntaxComment: {
      dark: RGBA.fromHex("#657e86"), // base01
      light: RGBA.fromHex("#7d8e8e"), // base1
    },
    syntaxNumber: {
      dark: RGBA.fromHex("#da5797"), // magenta
      light: RGBA.fromHex("#d33682"),
    },
    syntaxFunction: {
      dark: RGBA.fromHex("#268bd2"), // blue
      light: RGBA.fromHex("#2380c1"),
    },
    syntaxType: {
      dark: RGBA.fromHex("#b58900"), // yellow
      light: RGBA.fromHex("#967200"),
    },
    syntaxTag: {
      dark: RGBA.fromHex("#e65519"), // orange
      light: RGBA.fromHex("#cb4b16"),
    },
    syntaxAttr: {
      dark: RGBA.fromHex("#7b7fca"), // violet
      light: RGBA.fromHex("#6c71c4"),
    },
    syntaxPunctuation: {
      dark: RGBA.fromHex("#839496"), // base0
      light: RGBA.fromHex("#657b83"), // base00
    },

    // ── Diff ─────────────────────────────────────────────────
    diffAdded: {
      dark: RGBA.fromHex("#859900"),
      light: RGBA.fromHex("#859900"),
    },
    diffRemoved: {
      dark: RGBA.fromHex("#dc322f"),
      light: RGBA.fromHex("#dc322f"),
    },
    diffAddedBg: {
      dark: RGBA.fromHex("#0a3020"),
      light: RGBA.fromHex("#e8efc8"),
    },
    diffRemovedBg: {
      dark: RGBA.fromHex("#300a0a"),
      light: RGBA.fromHex("#f8d5d2"),
    },
  },
};
