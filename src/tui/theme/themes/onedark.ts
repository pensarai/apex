/**
 * One Dark — Dark: Atom One Dark, Light: Atom One Light
 *
 * Sourced from https://github.com/atom/one-dark-syntax
 * and https://github.com/atom/one-light-syntax
 */

import { RGBA } from "@opentui/core";
import type { ThemeDefinition } from "../types";

export const oneDark: ThemeDefinition = {
  name: "onedark",
  displayName: "One Dark",
  modes: ["dark", "light"],
  colors: {
    // ── Core UI ──────────────────────────────────────────────
    primary: {
      dark: RGBA.fromHex("#61afef"), // blue
      light: RGBA.fromHex("#4078f2"),
    },
    secondary: {
      dark: RGBA.fromHex("#c678dd"), // purple
      light: RGBA.fromHex("#a626a4"),
    },
    accent: {
      dark: RGBA.fromHex("#d19a66"), // orange
      light: RGBA.fromHex("#986801"),
    },

    // ── Text ─────────────────────────────────────────────────
    text: {
      dark: RGBA.fromHex("#abb2bf"), // fg
      light: RGBA.fromHex("#383a42"),
    },
    textMuted: {
      dark: RGBA.fromHex("#5c6370"), // comment
      light: RGBA.fromHex("#a0a1a7"),
    },

    // ── Backgrounds ──────────────────────────────────────────
    background: {
      dark: RGBA.fromHex("#282c34"), // bg
      light: RGBA.fromHex("#fafafa"),
    },
    backgroundPanel: {
      dark: RGBA.fromHex("#21252b"),
      light: RGBA.fromHex("#f0f0f0"),
    },
    backgroundElement: {
      dark: RGBA.fromHex("#2c313a"),
      light: RGBA.fromHex("#eaeaeb"),
    },
    backgroundOverlay: {
      dark: RGBA.fromInts(0, 0, 0, 200),
      light: RGBA.fromInts(0, 0, 0, 180),
    },
    backgroundSelected: {
      dark: RGBA.fromHex("#3e4451"),
      light: RGBA.fromHex("#d7d7d8"),
    },

    // ── Borders ──────────────────────────────────────────────
    border: {
      dark: RGBA.fromHex("#3e4451"),
      light: RGBA.fromHex("#d3d3d4"),
    },
    borderActive: {
      dark: RGBA.fromHex("#61afef"),
      light: RGBA.fromHex("#4078f2"),
    },
    borderSubtle: {
      dark: RGBA.fromHex("#2c313a"),
      light: RGBA.fromHex("#eaeaeb"),
    },

    // ── Semantic Status ──────────────────────────────────────
    error: {
      dark: RGBA.fromHex("#e06c75"), // red
      light: RGBA.fromHex("#e45649"),
    },
    warning: {
      dark: RGBA.fromHex("#e5c07b"), // yellow
      light: RGBA.fromHex("#c18401"),
    },
    success: {
      dark: RGBA.fromHex("#98c379"), // green
      light: RGBA.fromHex("#50a14f"),
    },
    info: {
      dark: RGBA.fromHex("#56b6c2"), // cyan
      light: RGBA.fromHex("#0184bc"),
    },

    // ── Permission Tiers ─────────────────────────────────────
    tierSafe: {
      dark: RGBA.fromHex("#98c379"),
      light: RGBA.fromHex("#50a14f"),
    },
    tierModerate: {
      dark: RGBA.fromHex("#e5c07b"),
      light: RGBA.fromHex("#c18401"),
    },
    tierRisky: {
      dark: RGBA.fromHex("#d19a66"),
      light: RGBA.fromHex("#986801"),
    },
    tierDangerous: {
      dark: RGBA.fromHex("#e06c75"),
      light: RGBA.fromHex("#e45649"),
    },

    // ── Markdown Rendering ───────────────────────────────────
    markdownCode: {
      dark: RGBA.fromHex("#98c379"),
      light: RGBA.fromHex("#50a14f"),
    },
    markdownLink: {
      dark: RGBA.fromHex("#56b6c2"),
      light: RGBA.fromHex("#0184bc"),
    },
    markdownHeading: {
      dark: RGBA.fromHex("#c678dd"),
      light: RGBA.fromHex("#a626a4"),
    },
    markdownStrong: {
      dark: RGBA.fromHex("#d19a66"),
      light: RGBA.fromHex("#986801"),
    },
    markdownEmph: {
      dark: RGBA.fromHex("#e5c07b"),
      light: RGBA.fromHex("#c18401"),
    },

    // ── Syntax Highlighting ──────────────────────────────────
    syntaxKeyword: {
      dark: RGBA.fromHex("#c678dd"), // purple
      light: RGBA.fromHex("#a626a4"),
    },
    syntaxString: {
      dark: RGBA.fromHex("#98c379"), // green
      light: RGBA.fromHex("#499348"),
    },
    syntaxComment: {
      dark: RGBA.fromHex("#656d7b"), // comment
      light: RGBA.fromHex("#909198"),
    },
    syntaxNumber: {
      dark: RGBA.fromHex("#d19a66"), // orange
      light: RGBA.fromHex("#986801"),
    },
    syntaxFunction: {
      dark: RGBA.fromHex("#61afef"), // blue
      light: RGBA.fromHex("#4078f2"),
    },
    syntaxType: {
      dark: RGBA.fromHex("#56b6c2"), // cyan
      light: RGBA.fromHex("#0184bc"),
    },
    syntaxTag: {
      dark: RGBA.fromHex("#e06c75"), // red
      light: RGBA.fromHex("#e45649"),
    },
    syntaxAttr: {
      dark: RGBA.fromHex("#e5c07b"), // yellow
      light: RGBA.fromHex("#ad7601"),
    },
    syntaxPunctuation: {
      dark: RGBA.fromHex("#abb2bf"), // fg
      light: RGBA.fromHex("#383a42"),
    },

    // ── Diff ─────────────────────────────────────────────────
    diffAdded: {
      dark: RGBA.fromHex("#98c379"),
      light: RGBA.fromHex("#50a14f"),
    },
    diffRemoved: {
      dark: RGBA.fromHex("#e06c75"),
      light: RGBA.fromHex("#e45649"),
    },
    diffAddedBg: {
      dark: RGBA.fromHex("#1e3329"),
      light: RGBA.fromHex("#d4eed4"),
    },
    diffRemovedBg: {
      dark: RGBA.fromHex("#3b2127"),
      light: RGBA.fromHex("#f5d5d5"),
    },
  },
};
