/**
 * Built-in Theme Barrel
 *
 * Imports all built-in theme definitions and provides a single function
 * to register them all with the theme registry.
 */

import { registerTheme } from "../registry";

import { apex } from "./apex";
import { ayu } from "./ayu";
import { catppuccin } from "./catppuccin";
import { dracula } from "./dracula";
import { everforest } from "./everforest";
import { flexoki } from "./flexoki";
import { github } from "./github";
import { gruvbox } from "./gruvbox";
import { kanagawa } from "./kanagawa";
import { material } from "./material";
import { monokai } from "./monokai";
import { nightfox } from "./nightfox";
import { nord } from "./nord";
import { oneDark } from "./onedark";
import { rosePine } from "./rose-pine";
import { solarized } from "./solarized";
import { tokyonight } from "./tokyonight";
import { vesper } from "./vesper";

const builtinThemes = [
  apex,
  ayu,
  catppuccin,
  dracula,
  everforest,
  flexoki,
  github,
  gruvbox,
  kanagawa,
  material,
  monokai,
  nightfox,
  nord,
  oneDark,
  rosePine,
  solarized,
  tokyonight,
  vesper,
];

export function registerBuiltinThemes(): void {
  for (const theme of builtinThemes) {
    registerTheme(theme);
  }
}
