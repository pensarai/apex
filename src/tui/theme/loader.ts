/**
 * Custom Theme JSON Loader
 *
 * Loads user-defined themes from ~/.pensar/themes/*.json at startup.
 * Invalid themes are logged as warnings and skipped.
 */

import fs from "fs/promises";
import path from "path";
import os from "os";
import { RGBA } from "@opentui/core";
import type { ThemeDefinition, ThemeColorsInput, ThemeColorValue } from "./types";
import { registerTheme } from "./registry";

const THEMES_DIR = path.join(os.homedir(), ".pensar", "themes");

/** All 30 required token names */
const REQUIRED_TOKENS = [
  "primary",
  "secondary",
  "accent",
  "text",
  "textMuted",
  "background",
  "backgroundPanel",
  "backgroundElement",
  "backgroundOverlay",
  "backgroundSelected",
  "border",
  "borderActive",
  "borderSubtle",
  "error",
  "warning",
  "success",
  "info",
  "tierSafe",
  "tierModerate",
  "tierRisky",
  "tierDangerous",
  "markdownCode",
  "markdownLink",
  "markdownHeading",
  "markdownStrong",
  "markdownEmph",
  "diffAdded",
  "diffRemoved",
  "diffAddedBg",
  "diffRemovedBg",
] as const;

/**
 * Parse a hex color string to an RGBA instance.
 * Supports "#RRGGBB" and "#RRGGBBAA" formats.
 */
function parseHexColor(hex: string): RGBA | null {
  if (typeof hex !== "string" || !hex.startsWith("#")) return null;
  try {
    return RGBA.fromHex(hex);
  } catch {
    return null;
  }
}

/**
 * Parse a JSON color value into a ThemeColorValue.
 * Supports:
 *   - "#hex" string (same color for both modes)
 *   - { "dark": "#hex", "light": "#hex" } object
 */
function parseColorValue(
  value: unknown,
  tokenName: string,
  themeName: string,
): ThemeColorValue | null {
  if (typeof value === "string") {
    const color = parseHexColor(value);
    if (!color) {
      console.warn(
        `Theme "${themeName}": invalid color "${value}" for token "${tokenName}"`,
      );
      return null;
    }
    return color;
  }

  if (
    typeof value === "object" &&
    value !== null &&
    "dark" in value &&
    "light" in value
  ) {
    const obj = value as { dark: string; light: string };
    const dark = parseHexColor(obj.dark);
    const light = parseHexColor(obj.light);
    if (!dark || !light) {
      console.warn(
        `Theme "${themeName}": invalid dark/light color for token "${tokenName}"`,
      );
      return null;
    }
    return { dark, light };
  }

  console.warn(
    `Theme "${themeName}": token "${tokenName}" must be a hex string or { dark, light } object`,
  );
  return null;
}

/**
 * Parse and validate a JSON object as a ThemeDefinition.
 * Returns null if validation fails.
 */
function parseThemeJson(
  json: unknown,
  filename: string,
): ThemeDefinition | null {
  if (typeof json !== "object" || json === null) {
    console.warn(`Theme "${filename}": root must be an object`);
    return null;
  }

  const obj = json as Record<string, unknown>;

  if (typeof obj.name !== "string" || !obj.name) {
    console.warn(`Theme "${filename}": missing or invalid "name" field`);
    return null;
  }

  const name = obj.name;
  const displayName =
    typeof obj.displayName === "string" ? obj.displayName : name;

  const modes: ("dark" | "light")[] = Array.isArray(obj.modes)
    ? (obj.modes.filter(
        (m) => m === "dark" || m === "light",
      ) as ("dark" | "light")[])
    : ["dark", "light"];

  if (typeof obj.colors !== "object" || obj.colors === null) {
    console.warn(`Theme "${name}": missing or invalid "colors" field`);
    return null;
  }

  const rawColors = obj.colors as Record<string, unknown>;
  const colors: Partial<ThemeColorsInput> = {};

  for (const token of REQUIRED_TOKENS) {
    if (!(token in rawColors)) {
      console.warn(`Theme "${name}": missing required token "${token}"`);
      return null;
    }
    const parsed = parseColorValue(rawColors[token], token, name);
    if (!parsed) return null;
    (colors as Record<string, ThemeColorValue>)[token] = parsed;
  }

  return {
    name,
    displayName,
    modes,
    colors: colors as ThemeColorsInput,
  };
}

/**
 * Load and register all custom themes from ~/.pensar/themes/.
 * Skips invalid themes with a warning. No-ops if the directory doesn't exist.
 */
export async function loadCustomThemes(): Promise<void> {
  try {
    await fs.access(THEMES_DIR);
  } catch {
    // Directory doesn't exist — not an error
    return;
  }

  let files: string[];
  try {
    const entries = await fs.readdir(THEMES_DIR);
    files = entries.filter((f) => f.endsWith(".json"));
  } catch (err) {
    console.warn(`Failed to read themes directory: ${err}`);
    return;
  }

  for (const file of files) {
    try {
      const content = await fs.readFile(path.join(THEMES_DIR, file), "utf-8");
      const json = JSON.parse(content);
      const theme = parseThemeJson(json, file);
      if (theme) {
        registerTheme(theme);
      }
    } catch (err) {
      console.warn(`Failed to load theme "${file}": ${err}`);
    }
  }
}
