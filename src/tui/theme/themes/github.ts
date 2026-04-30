/**
 * GitHub — Dark: GitHub Dark, Light: GitHub Light
 *
 * Sourced from https://github.com/projekt0n/github-nvim-theme
 */

import { RGBA } from "@opentui/core";
import type { ThemeDefinition } from "../types";

export const github: ThemeDefinition = {
  name: "github",
  displayName: "GitHub",
  modes: ["dark", "light"],
  colors: {
    // ── Core UI ──────────────────────────────────────────────
    primary: {
      dark: RGBA.fromHex("#58a6ff"), // blue
      light: RGBA.fromHex("#0969da"),
    },
    secondary: {
      dark: RGBA.fromHex("#d2a8ff"), // purple
      light: RGBA.fromHex("#8250df"),
    },
    accent: {
      dark: RGBA.fromHex("#79c0ff"), // light blue
      light: RGBA.fromHex("#0550ae"),
    },

    // ── Text ─────────────────────────────────────────────────
    text: {
      dark: RGBA.fromHex("#c9d1d9"), // fg
      light: RGBA.fromHex("#24292f"),
    },
    textMuted: {
      dark: RGBA.fromHex("#8b949e"), // muted
      light: RGBA.fromHex("#57606a"),
    },

    // ── Backgrounds ──────────────────────────────────────────
    background: {
      dark: RGBA.fromHex("#0d1117"), // canvas default
      light: RGBA.fromHex("#ffffff"),
    },
    backgroundPanel: {
      dark: RGBA.fromHex("#010409"), // canvas inset
      light: RGBA.fromHex("#f6f8fa"),
    },
    backgroundElement: {
      dark: RGBA.fromHex("#161b22"), // canvas subtle
      light: RGBA.fromHex("#f0f3f6"),
    },
    backgroundOverlay: {
      dark: RGBA.fromInts(0, 0, 0, 200),
      light: RGBA.fromInts(0, 0, 0, 180),
    },
    backgroundSelected: {
      dark: RGBA.fromHex("#1f2937"),
      light: RGBA.fromHex("#ddf4ff"),
    },

    // ── Borders ──────────────────────────────────────────────
    border: {
      dark: RGBA.fromHex("#30363d"),
      light: RGBA.fromHex("#d0d7de"),
    },
    borderActive: {
      dark: RGBA.fromHex("#58a6ff"),
      light: RGBA.fromHex("#0969da"),
    },
    borderSubtle: {
      dark: RGBA.fromHex("#21262d"),
      light: RGBA.fromHex("#e1e4e8"),
    },

    // ── Semantic Status ──────────────────────────────────────
    error: {
      dark: RGBA.fromHex("#f85149"), // danger
      light: RGBA.fromHex("#cf222e"),
    },
    warning: {
      dark: RGBA.fromHex("#d29922"), // attention
      light: RGBA.fromHex("#9a6700"),
    },
    success: {
      dark: RGBA.fromHex("#3fb950"), // success
      light: RGBA.fromHex("#1a7f37"),
    },
    info: {
      dark: RGBA.fromHex("#58a6ff"), // accent
      light: RGBA.fromHex("#0969da"),
    },

    // ── Permission Tiers ─────────────────────────────────────
    tierSafe: {
      dark: RGBA.fromHex("#3fb950"),
      light: RGBA.fromHex("#1a7f37"),
    },
    tierModerate: {
      dark: RGBA.fromHex("#d29922"),
      light: RGBA.fromHex("#9a6700"),
    },
    tierRisky: {
      dark: RGBA.fromHex("#e3b341"),
      light: RGBA.fromHex("#bf8700"),
    },
    tierDangerous: {
      dark: RGBA.fromHex("#f85149"),
      light: RGBA.fromHex("#cf222e"),
    },

    // ── Markdown Rendering ───────────────────────────────────
    markdownCode: {
      dark: RGBA.fromHex("#3fb950"),
      light: RGBA.fromHex("#1a7f37"),
    },
    markdownLink: {
      dark: RGBA.fromHex("#58a6ff"),
      light: RGBA.fromHex("#0969da"),
    },
    markdownHeading: {
      dark: RGBA.fromHex("#d2a8ff"),
      light: RGBA.fromHex("#8250df"),
    },
    markdownStrong: {
      dark: RGBA.fromHex("#c9d1d9"),
      light: RGBA.fromHex("#24292f"),
    },
    markdownEmph: {
      dark: RGBA.fromHex("#d29922"),
      light: RGBA.fromHex("#9a6700"),
    },

    // ── Syntax Highlighting ──────────────────────────────────
    syntaxKeyword: {
      dark: RGBA.fromHex("#ff7b72"), // red
      light: RGBA.fromHex("#cf222e"),
    },
    syntaxString: {
      dark: RGBA.fromHex("#a5d6ff"), // light blue (string)
      light: RGBA.fromHex("#0a3069"),
    },
    syntaxComment: {
      dark: RGBA.fromHex("#8b949e"), // muted
      light: RGBA.fromHex("#57606a"),
    },
    syntaxNumber: {
      dark: RGBA.fromHex("#79c0ff"), // blue
      light: RGBA.fromHex("#0550ae"),
    },
    syntaxFunction: {
      dark: RGBA.fromHex("#d2a8ff"), // purple
      light: RGBA.fromHex("#8250df"),
    },
    syntaxType: {
      dark: RGBA.fromHex("#ffa657"), // orange (type)
      light: RGBA.fromHex("#953800"),
    },
    syntaxTag: {
      dark: RGBA.fromHex("#7ee787"), // green (tag)
      light: RGBA.fromHex("#116329"),
    },
    syntaxAttr: {
      dark: RGBA.fromHex("#79c0ff"), // blue
      light: RGBA.fromHex("#0550ae"),
    },
    syntaxPunctuation: {
      dark: RGBA.fromHex("#c9d1d9"), // fg
      light: RGBA.fromHex("#24292f"),
    },

    // ── Diff ─────────────────────────────────────────────────
    diffAdded: {
      dark: RGBA.fromHex("#3fb950"),
      light: RGBA.fromHex("#1a7f37"),
    },
    diffRemoved: {
      dark: RGBA.fromHex("#f85149"),
      light: RGBA.fromHex("#cf222e"),
    },
    diffAddedBg: {
      dark: RGBA.fromHex("#12261e"),
      light: RGBA.fromHex("#dafbe1"),
    },
    diffRemovedBg: {
      dark: RGBA.fromHex("#2d1215"),
      light: RGBA.fromHex("#ffebe9"),
    },
  },
};
