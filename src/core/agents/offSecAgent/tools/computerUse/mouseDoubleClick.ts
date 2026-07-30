import { tool } from "ai";
import { z } from "zod";
import { mouseDoubleClickCommand } from "../../../../desktop";
import type { ToolContext } from "../types";
import { resolveDesktopOs, runDesktopCommand } from "./runtime";

/** Double-click (left button) at a specific (x, y) coordinate. */
export function computerMouseDoubleClick(_ctx: ToolContext) {
  return tool({
    description: `Double-click the mouse at a specific position on screen.

Performs a left double-click at the given (x, y) coordinates — use for opening
files, selecting a word, or activating list items.`,
    inputSchema: z.object({
      x: z.number().describe("X coordinate to double-click at"),
      y: z.number().describe("Y coordinate to double-click at"),
      toolCallDescription: z
        .string()
        .describe("Why you are double-clicking at this position"),
    }),
    execute: async ({ x, y }) => {
      const os = resolveDesktopOs();
      return runDesktopCommand(
        mouseDoubleClickCommand(os, x, y),
        `Double-clicked at (${x}, ${y})`,
      );
    },
  });
}
