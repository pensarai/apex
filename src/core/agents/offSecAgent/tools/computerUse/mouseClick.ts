import { tool } from "ai";
import { z } from "zod";
import type { ToolContext } from "../types";
import { getDesktopBackend } from "./platform";

export function computerMouseClick(_ctx: ToolContext) {
  return tool({
    description: `Click the mouse at a specific position on screen.

Performs a mouse click at the given (x, y) coordinates. Supports left, right,
and middle button clicks. If coordinates are omitted, clicks at the current
mouse position.

Use after taking a screenshot to identify where to click.`,
    inputSchema: z.object({
      x: z.number().describe("X coordinate to click at"),
      y: z.number().describe("Y coordinate to click at"),
      button: z
        .enum(["left", "right", "middle"])
        .optional()
        .default("left")
        .describe("Mouse button to click"),
      toolCallDescription: z
        .string()
        .describe("Why you are clicking at this position"),
    }),
    execute: async ({
      x,
      y,
      button,
    }): Promise<{ success: boolean; message: string }> => {
      try {
        const backend = getDesktopBackend();
        backend.mouseClick(button, x, y);
        return {
          success: true,
          message: `Clicked ${button ?? "left"} button at (${x}, ${y})`,
        };
      } catch (error) {
        const msg = error instanceof Error ? error.message : String(error);
        return { success: false, message: `Mouse click failed: ${msg}` };
      }
    },
  });
}
