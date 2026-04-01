import { tool } from "ai";
import { z } from "zod";
import type { ToolContext } from "../types";
import { getDesktopBackend } from "./platform";

export function computerMouseDrag(_ctx: ToolContext) {
  return tool({
    description: `Drag the mouse from one position to another.

Performs a click-and-drag from (startX, startY) to (endX, endY).
Useful for selecting text, moving elements, or interacting with sliders.`,
    inputSchema: z.object({
      startX: z.number().describe("Starting X coordinate"),
      startY: z.number().describe("Starting Y coordinate"),
      endX: z.number().describe("Ending X coordinate"),
      endY: z.number().describe("Ending Y coordinate"),
      toolCallDescription: z
        .string()
        .describe("Why you are performing this drag operation"),
    }),
    execute: async ({
      startX,
      startY,
      endX,
      endY,
    }): Promise<{ success: boolean; message: string }> => {
      try {
        const backend = getDesktopBackend();
        backend.mouseDrag(startX, startY, endX, endY);
        return {
          success: true,
          message: `Dragged from (${startX}, ${startY}) to (${endX}, ${endY})`,
        };
      } catch (error) {
        const msg = error instanceof Error ? error.message : String(error);
        return { success: false, message: `Mouse drag failed: ${msg}` };
      }
    },
  });
}
