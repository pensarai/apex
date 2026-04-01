import { tool } from "ai";
import { z } from "zod";
import type { ToolContext } from "../types";
import { getDesktopBackend } from "./platform";

export function computerMouseMove(_ctx: ToolContext) {
  return tool({
    description: `Move the mouse cursor to specific coordinates on screen.

Moves the mouse to the given (x, y) coordinates without clicking.
Useful for hovering over elements to trigger tooltips or menus.`,
    inputSchema: z.object({
      x: z.number().describe("X coordinate to move to"),
      y: z.number().describe("Y coordinate to move to"),
      toolCallDescription: z
        .string()
        .describe("Why you are moving the mouse to this position"),
    }),
    execute: async ({
      x,
      y,
    }): Promise<{ success: boolean; message: string }> => {
      try {
        const backend = getDesktopBackend();
        backend.mouseMove(x, y);
        return {
          success: true,
          message: `Mouse moved to (${x}, ${y})`,
        };
      } catch (error) {
        const msg = error instanceof Error ? error.message : String(error);
        return { success: false, message: `Mouse move failed: ${msg}` };
      }
    },
  });
}
