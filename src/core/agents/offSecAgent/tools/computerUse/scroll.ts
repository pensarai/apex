import { tool } from "ai";
import { z } from "zod";
import { scrollCommand } from "../../../../desktop";
import type { ToolContext } from "../types";
import { resolveDesktopOs, runDesktopCommand } from "./runtime";

/** Scroll the mouse wheel; positive = down, negative = up. */
export function computerScroll(_ctx: ToolContext) {
  return tool({
    description: `Scroll the mouse wheel at the current or a specified position.

Positive amount scrolls down, negative scrolls up. Each unit is one wheel notch.
Optionally pass (x, y) to scroll at a specific position.`,
    inputSchema: z.object({
      amount: z
        .number()
        .describe(
          "Scroll amount. Positive = down, negative = up (in notches).",
        ),
      x: z.number().optional().describe("X coordinate to scroll at"),
      y: z.number().optional().describe("Y coordinate to scroll at"),
      toolCallDescription: z.string().describe("Why you are scrolling"),
    }),
    execute: async ({ amount, x, y }) => {
      const os = resolveDesktopOs();
      const direction = amount > 0 ? "down" : "up";
      const pos = x != null && y != null ? ` at (${x}, ${y})` : "";
      return runDesktopCommand(
        scrollCommand(os, amount, x, y),
        `Scrolled ${direction} ${Math.abs(amount)} notch(es)${pos}`,
      );
    },
  });
}
