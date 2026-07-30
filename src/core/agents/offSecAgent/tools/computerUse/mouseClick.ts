import { tool } from "ai";
import { z } from "zod";
import { mouseClickCommand } from "../../../../desktop";
import type { ToolContext } from "../types";
import { resolveDesktopOs, runDesktopCommand } from "./runtime";

/**
 * Click the mouse at a specific (x, y) coordinate. Identify the target
 * coordinate from a prior `computer_screenshot`.
 */
export function computerMouseClick(_ctx: ToolContext) {
  return tool({
    description: `Click the mouse at a specific position on screen.

Performs a mouse click at the given (x, y) coordinates. Supports left, right,
and middle button clicks. Take a screenshot first to identify where to click —
coordinates are absolute screen pixels, (0, 0) at the top-left.`,
    inputSchema: z.object({
      x: z.number().describe("X coordinate to click at"),
      y: z.number().describe("Y coordinate to click at"),
      button: z
        .enum(["left", "right", "middle"])
        .default("left")
        .describe("Mouse button to click"),
      toolCallDescription: z
        .string()
        .describe("Why you are clicking at this position"),
    }),
    execute: async ({ x, y, button }) => {
      const os = resolveDesktopOs();
      return runDesktopCommand(
        mouseClickCommand(os, button, x, y),
        `Clicked ${button} button at (${x}, ${y})`,
      );
    },
  });
}
