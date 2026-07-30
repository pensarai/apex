import { tool } from "ai";
import { z } from "zod";
import { mouseMoveCommand } from "../../../../desktop";
import type { ToolContext } from "../types";
import { resolveDesktopOs, runDesktopCommand } from "./runtime";

/** Move the cursor to a specific (x, y) coordinate without clicking. */
export function computerMouseMove(_ctx: ToolContext) {
  return tool({
    description: `Move the mouse cursor to specific coordinates on screen.

Moves the cursor to (x, y) without clicking — use to hover over an element to
reveal tooltips or menus before interacting.`,
    inputSchema: z.object({
      x: z.number().describe("X coordinate to move to"),
      y: z.number().describe("Y coordinate to move to"),
      toolCallDescription: z
        .string()
        .describe("Why you are moving the mouse to this position"),
    }),
    execute: async ({ x, y }) => {
      const os = resolveDesktopOs();
      return runDesktopCommand(
        mouseMoveCommand(os, x, y),
        `Moved mouse to (${x}, ${y})`,
      );
    },
  });
}
