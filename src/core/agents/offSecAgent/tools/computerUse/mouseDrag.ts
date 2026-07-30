import { tool } from "ai";
import { z } from "zod";
import { mouseDragCommand } from "../../../../desktop";
import type { ToolContext } from "../types";
import { resolveDesktopOs, runDesktopCommand } from "./runtime";

/** Click-and-drag from one coordinate to another. */
export function computerMouseDrag(_ctx: ToolContext) {
  return tool({
    description: `Drag the mouse from one position to another.

Performs a left-button click-and-drag from (startX, startY) to (endX, endY).
Use for selecting text, moving elements, or dragging sliders.`,
    inputSchema: z.object({
      startX: z.number().describe("Starting X coordinate"),
      startY: z.number().describe("Starting Y coordinate"),
      endX: z.number().describe("Ending X coordinate"),
      endY: z.number().describe("Ending Y coordinate"),
      toolCallDescription: z
        .string()
        .describe("Why you are performing this drag operation"),
    }),
    execute: async ({ startX, startY, endX, endY }) => {
      const os = resolveDesktopOs();
      return runDesktopCommand(
        mouseDragCommand(os, startX, startY, endX, endY),
        `Dragged from (${startX}, ${startY}) to (${endX}, ${endY})`,
      );
    },
  });
}
