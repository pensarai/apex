import { tool } from "ai";
import { z } from "zod";
import type { ToolContext } from "../types";
import { getDesktopBackend } from "./platform";

export function computerKeyPress(_ctx: ToolContext) {
  return tool({
    description: `Press a key or key combination.

Sends a key press event. Supports single keys and modifier combinations.

Key names follow xdotool conventions on Linux, cliclick on macOS:

Single keys: Return, Escape, Tab, BackSpace, Delete, space, Up, Down, Left, Right,
  Home, End, Page_Up, Page_Down, F1-F12

Modifier combos (use + separator): ctrl+c, ctrl+v, ctrl+a, alt+Tab, alt+F4,
  ctrl+shift+t, super+l (Windows/Super key)

Common examples:
- "Return"        — press Enter
- "Escape"        — press Escape
- "ctrl+c"        — copy
- "ctrl+v"        — paste
- "ctrl+a"        — select all
- "alt+Tab"       — switch windows
- "ctrl+shift+t"  — reopen closed tab
- "super+l"       — lock screen`,
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
    execute: async ({
      keys,
    }): Promise<{ success: boolean; message: string }> => {
      try {
        const backend = getDesktopBackend();
        backend.keyPress(keys);
        return {
          success: true,
          message: `Pressed key(s): ${keys}`,
        };
      } catch (error) {
        const msg = error instanceof Error ? error.message : String(error);
        return { success: false, message: `Key press failed: ${msg}` };
      }
    },
  });
}
