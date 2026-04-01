import { tool } from "ai";
import { z } from "zod";
import type { ToolContext } from "../types";
import { getDesktopBackend } from "./platform";

export function computerTypeText(_ctx: ToolContext) {
  return tool({
    description: `Type text using the keyboard.

Types the given text string as if it were being typed on a physical keyboard.
Special characters and unicode are handled automatically.

For key combinations (Ctrl+C, Alt+Tab, etc.) use computer_key_press instead.`,
    inputSchema: z.object({
      text: z.string().describe("The text to type"),
      toolCallDescription: z.string().describe("Why you are typing this text"),
    }),
    execute: async ({
      text,
    }): Promise<{ success: boolean; message: string }> => {
      try {
        const backend = getDesktopBackend();
        backend.typeText(text);
        const preview = text.length > 50 ? text.substring(0, 50) + "…" : text;
        return {
          success: true,
          message: `Typed: "${preview}"`,
        };
      } catch (error) {
        const msg = error instanceof Error ? error.message : String(error);
        return { success: false, message: `Type text failed: ${msg}` };
      }
    },
  });
}
