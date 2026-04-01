import { tool } from "ai";
import { z } from "zod";
import type { ToolContext } from "../types";
import { getDesktopBackend } from "./platform";

export function computerMouseDoubleClick(_ctx: ToolContext) {
  return tool({
    description: `Double-click the mouse at a specific position on screen.

Performs a double-click at the given (x, y) coordinates.
If coordinates are omitted, double-clicks at the current mouse position.`,
    inputSchema: z.object({
      x: z.number().optional().describe("X coordinate to double-click at"),
      y: z.number().optional().describe("Y coordinate to double-click at"),
      toolCallDescription: z
        .string()
        .describe("Why you are double-clicking at this position"),
    }),
    execute: async ({
      x,
      y,
    }): Promise<{ success: boolean; message: string }> => {
      try {
        const backend = getDesktopBackend();
        backend.mouseDoubleClick(x, y);
        const pos =
          x != null && y != null ? `(${x}, ${y})` : "current position";
        return {
          success: true,
          message: `Double-clicked at ${pos}`,
        };
      } catch (error) {
        const msg = error instanceof Error ? error.message : String(error);
        return {
          success: false,
          message: `Double-click failed: ${msg}`,
        };
      }
    },
  });
}
