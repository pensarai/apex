import { tool } from "ai";
import { z } from "zod";
import type { ToolContext } from "../types";
import { getDesktopBackend } from "./platform";

export function computerScroll(_ctx: ToolContext) {
  return tool({
    description: `Scroll the mouse wheel at the current or specified position.

Positive amount scrolls down, negative scrolls up. Each unit is one
"click" of the scroll wheel.

Optionally specify coordinates to scroll at a specific position.`,
    inputSchema: z.object({
      amount: z
        .number()
        .describe(
          "Scroll amount. Positive = down, negative = up. Each unit is ~3 lines.",
        ),
      x: z.number().optional().describe("X coordinate to scroll at"),
      y: z.number().optional().describe("Y coordinate to scroll at"),
      toolCallDescription: z.string().describe("Why you are scrolling"),
    }),
    execute: async ({
      amount,
      x,
      y,
    }): Promise<{ success: boolean; message: string }> => {
      try {
        const backend = getDesktopBackend();
        backend.scroll(amount, x, y);
        const direction = amount > 0 ? "down" : "up";
        const pos = x != null && y != null ? ` at (${x}, ${y})` : "";
        return {
          success: true,
          message: `Scrolled ${direction} ${Math.abs(amount)} clicks${pos}`,
        };
      } catch (error) {
        const msg = error instanceof Error ? error.message : String(error);
        return { success: false, message: `Scroll failed: ${msg}` };
      }
    },
  });
}
