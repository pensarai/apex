import { tool } from "ai";
import { z } from "zod";
import type { ToolContext } from "../types";
import { getDesktopBackend } from "./platform";

export function computerScreenInfo(_ctx: ToolContext) {
  return tool({
    description: `Get information about the current screen state.

Returns the screen dimensions, current mouse position, and the title
of the currently active window. Use this to orient yourself before
interacting with the desktop.`,
    inputSchema: z.object({
      toolCallDescription: z
        .string()
        .describe("Why you need screen information"),
    }),
    execute: async (): Promise<{
      success: boolean;
      screen?: { width: number; height: number };
      mousePosition?: { x: number; y: number };
      activeWindowTitle?: string;
      message: string;
    }> => {
      try {
        const backend = getDesktopBackend();
        const screen = backend.getScreenSize();
        const mouse = backend.getMousePosition();
        const title = backend.getActiveWindowTitle();

        return {
          success: true,
          screen,
          mousePosition: mouse,
          activeWindowTitle: title,
          message: `Screen: ${screen.width}x${screen.height}, Mouse: (${mouse.x}, ${mouse.y}), Active window: "${title}"`,
        };
      } catch (error) {
        const msg = error instanceof Error ? error.message : String(error);
        return { success: false, message: `Failed to get screen info: ${msg}` };
      }
    },
  });
}
