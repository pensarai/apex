import { tool } from "ai";
import { z } from "zod";
import { typeTextCommand } from "../../../../desktop";
import type { ToolContext } from "../types";
import { resolveDesktopOs, runDesktopCommand } from "./runtime";

/** Type literal text via the keyboard. Click the target field first. */
export function computerTypeText(_ctx: ToolContext) {
  return tool({
    description: `Type text using the keyboard.

Types the given string as if typed on a physical keyboard. Click the target
input field first so it has focus. For key combinations (Ctrl+C, Alt+Tab, etc.)
use computer_key_press instead.`,
    inputSchema: z.object({
      text: z.string().describe("The text to type"),
      toolCallDescription: z.string().describe("Why you are typing this text"),
    }),
    execute: async ({ text }) => {
      const os = resolveDesktopOs();
      const preview = text.length > 50 ? `${text.slice(0, 50)}…` : text;
      return runDesktopCommand(
        typeTextCommand(os, text),
        `Typed: "${preview}"`,
      );
    },
  });
}
