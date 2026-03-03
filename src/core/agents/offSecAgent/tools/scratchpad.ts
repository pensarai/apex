import { tool } from "ai";
import { z } from "zod";
import { join } from "path";
import {
  writeFileSync,
  readFileSync,
  appendFileSync,
  readdirSync,
  mkdirSync,
  existsSync,
} from "fs";
import type { ToolContext } from "./types";

const APPEND_PREFIX = "---APPEND---\n";

export function scratchpad(ctx: ToolContext) {
  const scratchpadDir = ctx.session.scratchpadPath;

  // Ensure directory exists on tool creation
  if (!existsSync(scratchpadDir)) {
    mkdirSync(scratchpadDir, { recursive: true });
  }

  return tool({
    description: `Persist and retrieve notes across your context window. Use this to save key findings, credentials, successful payloads, and endpoint discoveries so they survive context clearing.

Actions:
- write: Save content to a named note. Prefix content with '---APPEND---\\n' to append instead of overwrite.
- read: Read a named note.
- list: List all saved notes.`,

    inputSchema: z.object({
      action: z.enum(["write", "read", "list"]),
      key: z
        .string()
        .optional()
        .describe(
          "Note identifier (e.g. 'progress', 'endpoints', 'credentials')",
        ),
      content: z
        .string()
        .optional()
        .describe(
          "Content to write (required for write). Prefix with '---APPEND---\\n' to append.",
        ),
      toolCallDescription: z
        .string()
        .describe("Description of what you're saving/reading"),
    }),

    execute: async ({ action, key, content }) => {
      switch (action) {
        case "write": {
          if (!key) return { success: false, error: "key is required for write" };
          if (!content) return { success: false, error: "content is required for write" };

          const filePath = join(scratchpadDir, `${key}.md`);

          if (content.startsWith(APPEND_PREFIX)) {
            const appendContent = content.slice(APPEND_PREFIX.length);
            appendFileSync(filePath, appendContent, "utf-8");
            return {
              success: true,
              path: filePath,
              bytesWritten: Buffer.byteLength(appendContent, "utf-8"),
            };
          }

          writeFileSync(filePath, content, "utf-8");
          return {
            success: true,
            path: filePath,
            bytesWritten: Buffer.byteLength(content, "utf-8"),
          };
        }

        case "read": {
          if (!key) return { success: false, error: "key is required for read" };

          const filePath = join(scratchpadDir, `${key}.md`);
          if (!existsSync(filePath)) {
            return { success: false, error: `Note '${key}' not found` };
          }

          const fileContent = readFileSync(filePath, "utf-8");
          return { success: true, content: fileContent };
        }

        case "list": {
          if (!existsSync(scratchpadDir)) {
            return { success: true, notes: [] };
          }

          const notes = readdirSync(scratchpadDir)
            .filter((f) => f.endsWith(".md"))
            .map((f) => f.replace(/\.md$/, ""));

          return { success: true, notes };
        }

        default:
          return { success: false, error: `Unknown action: ${action}` };
      }
    },
  });
}
