/**
 * Kanagawa — Dark: Wave, Light: Lotus
 *
 * Sourced from https://github.com/rebelot/kanagawa.nvim
 */

import { RGBA } from "@opentui/core";
import type { ThemeDefinition } from "../types";

export const kanagawa: ThemeDefinition = {
  name: "kanagawa",
  displayName: "Kanagawa",
  modes: ["dark", "light"],
  colors: {
    // ── Core UI ──────────────────────────────────────────────
    primary: {
      dark: RGBA.fromHex("#7e9cd8"), // crystalBlue (wave)
      light: RGBA.fromHex("#4d699b"), // crystalBlue (lotus)
    },
    secondary: {
      dark: RGBA.fromHex("#957fb8"), // oniViolet (wave)
      light: RGBA.fromHex("#624c83"), // oniViolet (lotus)
    },
    accent: {
      dark: RGBA.fromHex("#e6c384"), // carpYellow (wave)
      light: RGBA.fromHex("#836930"), // carpYellow (lotus)
    },

    // ── Text ─────────────────────────────────────────────────
    text: {
      dark: RGBA.fromHex("#dcd7ba"), // fujiWhite (wave)
      light: RGBA.fromHex("#545464"), // fujiWhite equiv (lotus)
    },
    textMuted: {
      dark: RGBA.fromHex("#727169"), // fujiGray (wave)
      light: RGBA.fromHex("#8a8980"), // fujiGray (lotus)
    },

    // ── Backgrounds ──────────────────────────────────────────
    background: {
      dark: RGBA.fromHex("#1f1f28"), // sumiInk3 (wave)
      light: RGBA.fromHex("#f2ecbc"), // lotusWhite3 (lotus)
    },
    backgroundPanel: {
      dark: RGBA.fromHex("#16161d"), // sumiInk0 (wave)
      light: RGBA.fromHex("#f6f0c2"), // lotusWhite4 (lotus)
    },
    backgroundElement: {
      dark: RGBA.fromHex("#2a2a37"), // sumiInk4 (wave)
      light: RGBA.fromHex("#e5ddb0"), // lotusWhite1 (lotus)
    },
    backgroundOverlay: {
      dark: RGBA.fromInts(0, 0, 0, 200),
      light: RGBA.fromInts(0, 0, 0, 180),
    },
    backgroundSelected: {
      dark: RGBA.fromHex("#2d4f67"), // waveBlue2 (wave)
      light: RGBA.fromHex("#c9cbd1"), // lotusViolet (lotus)
    },

    // ── Borders ──────────────────────────────────────────────
    border: {
      dark: RGBA.fromHex("#54546d"), // sumiInk6 (wave)
      light: RGBA.fromHex("#c7c7d0"),
    },
    borderActive: {
      dark: RGBA.fromHex("#7e9cd8"), // crystalBlue
      light: RGBA.fromHex("#4d699b"),
    },
    borderSubtle: {
      dark: RGBA.fromHex("#2a2a37"), // sumiInk4
      light: RGBA.fromHex("#e5ddb0"),
    },

    // ── Semantic Status ──────────────────────────────────────
    error: {
      dark: RGBA.fromHex("#e82424"), // samuraiRed (wave)
      light: RGBA.fromHex("#c84053"), // lotusRed (lotus)
    },
    warning: {
      dark: RGBA.fromHex("#ff9e3b"), // roninYellow (wave)
      light: RGBA.fromHex("#cc6d00"),
    },
    success: {
      dark: RGBA.fromHex("#76946a"), // autumnGreen (wave)
      light: RGBA.fromHex("#6f894e"), // lotusGreen (lotus)
    },
    info: {
      dark: RGBA.fromHex("#7fb4ca"), // springBlue (wave)
      light: RGBA.fromHex("#4d699b"),
    },

    // ── Permission Tiers ─────────────────────────────────────
    tierSafe: {
      dark: RGBA.fromHex("#76946a"),
      light: RGBA.fromHex("#6f894e"),
    },
    tierModerate: {
      dark: RGBA.fromHex("#e6c384"), // carpYellow
      light: RGBA.fromHex("#836930"),
    },
    tierRisky: {
      dark: RGBA.fromHex("#ff9e3b"), // roninYellow
      light: RGBA.fromHex("#cc6d00"),
    },
    tierDangerous: {
      dark: RGBA.fromHex("#e82424"),
      light: RGBA.fromHex("#c84053"),
    },

    // ── Markdown Rendering ───────────────────────────────────
    markdownCode: {
      dark: RGBA.fromHex("#76946a"), // autumnGreen
      light: RGBA.fromHex("#6f894e"),
    },
    markdownLink: {
      dark: RGBA.fromHex("#7fb4ca"), // springBlue
      light: RGBA.fromHex("#4d699b"),
    },
    markdownHeading: {
      dark: RGBA.fromHex("#957fb8"), // oniViolet
      light: RGBA.fromHex("#624c83"),
    },
    markdownStrong: {
      dark: RGBA.fromHex("#ff9e3b"), // roninYellow
      light: RGBA.fromHex("#cc6d00"),
    },
    markdownEmph: {
      dark: RGBA.fromHex("#e6c384"), // carpYellow
      light: RGBA.fromHex("#836930"),
    },

    // ── Syntax Highlighting ──────────────────────────────────
    syntaxKeyword: {
      dark: RGBA.fromHex("#957fb8"), // oniViolet (wave)
      light: RGBA.fromHex("#624c83"), // oniViolet (lotus)
    },
    syntaxString: {
      dark: RGBA.fromHex("#98bb6c"), // springGreen (wave)
      light: RGBA.fromHex("#6f894e"), // lotusGreen
    },
    syntaxComment: {
      dark: RGBA.fromHex("#727169"), // fujiGray (wave)
      light: RGBA.fromHex("#8a8980"), // fujiGray (lotus)
    },
    syntaxNumber: {
      dark: RGBA.fromHex("#d27e99"), // sakuraPink (wave)
      light: RGBA.fromHex("#b35b79"), // lotusPink
    },
    syntaxFunction: {
      dark: RGBA.fromHex("#7e9cd8"), // crystalBlue (wave)
      light: RGBA.fromHex("#4d699b"), // crystalBlue (lotus)
    },
    syntaxType: {
      dark: RGBA.fromHex("#7fb4ca"), // springBlue (wave)
      light: RGBA.fromHex("#4d699b"),
    },
    syntaxTag: {
      dark: RGBA.fromHex("#e6c384"), // carpYellow (wave)
      light: RGBA.fromHex("#836930"),
    },
    syntaxAttr: {
      dark: RGBA.fromHex("#6a9589"), // waveAqua2 (wave)
      light: RGBA.fromHex("#5a7a68"),
    },
    syntaxPunctuation: {
      dark: RGBA.fromHex("#9cabca"), // oldWhite (wave)
      light: RGBA.fromHex("#68687a"),
    },

    // ── Diff ─────────────────────────────────────────────────
    diffAdded: {
      dark: RGBA.fromHex("#76946a"),
      light: RGBA.fromHex("#6f894e"),
    },
    diffRemoved: {
      dark: RGBA.fromHex("#c34043"), // autumnRed (wave)
      light: RGBA.fromHex("#c84053"),
    },
    diffAddedBg: {
      dark: RGBA.fromHex("#1a2a20"),
      light: RGBA.fromHex("#d8e4c8"),
    },
    diffRemovedBg: {
      dark: RGBA.fromHex("#31161b"),
      light: RGBA.fromHex("#f0d0d5"),
    },
  },
};
