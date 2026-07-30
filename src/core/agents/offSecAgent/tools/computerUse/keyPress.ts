import { tool } from "ai";
import { z } from "zod";
import { keyPressCommand } from "../../../../desktop";
import type { ToolContext } from "../types";
import { resolveDesktopOs, runDesktopCommand } from "./runtime";

/** Press a single key or a `+`-separated key combination. */
export function computerKeyPress(_ctx: ToolContext) {
  return tool({
    description: `Press a key or key combination.

Combos are "+"-separated. Key names follow xdotool conventions and are
translated per OS automatically.

Single keys: Return, Escape, Tab, BackSpace, Delete, space, Up, Down, Left,
  Right, Home, End, Page_Up, Page_Down, F1-F12
Modifier combos: ctrl+c, ctrl+v, ctrl+a, alt+Tab, alt+F4, ctrl+shift+t

Examples: "Return", "Escape", "ctrl+c", "ctrl+v", "alt+Tab".`,
    inputSchema: z.object({
      keys: z
        .string()
        .describe(
          'Key or key combination to press (e.g. "Return", "ctrl+c", "alt+Tab")',
        ),
      toolCallDescription: z
        .string()
        .describe("Why you are pressing this key combination"),
    }),
    execute: async ({ keys }) => {
      const os = resolveDesktopOs();
      return runDesktopCommand(
        keyPressCommand(os, keys),
        `Pressed key(s): ${keys}`,
      );
    },
  });
}
