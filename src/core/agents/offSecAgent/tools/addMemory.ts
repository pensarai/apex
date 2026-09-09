import { tool } from "ai";
import { z } from "zod";
import {
  addMemory as coreAddMemory,
  MEMORY_CATEGORIES,
  type MemoryCategory,
} from "../../../memory";
import type { ToolContext } from "./types";

const addMemoryInputSchema = z.object({
  title: z
    .string()
    .describe("Short, descriptive title for the memory (used to generate id)"),
  content: z.string().describe("Free-form text content to persist as a memory"),
  category: z
    .enum(MEMORY_CATEGORIES)
    .optional()
    .describe(
      'Storage category: "app" for application-specific knowledge, ' +
        '"framework" for framework-specific knowledge, or omit for the ' +
        '"general" catch-all',
    ),
  tags: z
    .array(z.string())
    .optional()
    .describe("Optional tags for categorisation and filtering"),
  toolCallDescription: z
    .string()
    .optional()
    .describe(
      "A concise, human-readable description of what this tool call is doing (e.g., 'Saving XSS payload pattern')",
    ),
});

type AddMemoryInput = z.infer<typeof addMemoryInputSchema>;

export type AddMemoryResult = {
  success: boolean;
  error: string;
  id?: string;
  category?: MemoryCategory;
  title?: string;
};

export function addMemory(_ctx: ToolContext) {
  return tool({
    description: `Save a piece of knowledge to persistent memory.

Memories are stored across sessions in ~/.pensar/memories/ and survive restarts.
They are organised into categories:
  - "app"       — application-specific notes (e.g. target quirks, endpoints)
  - "framework" — framework-specific notes (e.g. Rails tricks, Django patterns)
  - "general"   — catch-all (default when category is omitted)

IMPORTANT: Before adding a new memory, always use list_memories first to check
for existing memories that overlap with what you intend to save. If a relevant
memory already exists, update it (delete + re-add) rather than creating a
duplicate. This keeps the memory store clean and avoids conflicting entries.

Use this to record reusable techniques, target-specific notes, credential
patterns, useful payloads, or any information worth remembering for future
engagements.`,
    inputSchema: addMemoryInputSchema,
    execute: async ({
      title,
      content,
      category,
      tags,
    }): Promise<AddMemoryResult> => {
      try {
        const memory = await coreAddMemory({ title, content, category, tags });
        return {
          success: true,
          error: "",
          id: memory.id,
          category: memory.category,
          title: memory.title,
        };
      } catch (err: unknown) {
        return {
          success: false,
          error: err instanceof Error ? err.message : String(err),
        };
      }
    },
  });
}
