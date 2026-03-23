import { tool } from "ai";
import { z } from "zod";
import {
  addMemory as coreAddMemory,
  MEMORY_CATEGORIES,
  type MemoryCategory,
} from "../../../memory";
import type { ToolContext } from "./types";

export const addMemoryInputSchema = z.object({
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
});

export type AddMemoryInput = z.infer<typeof addMemoryInputSchema>;

export type AddMemoryResult = {
  success: boolean;
  error: string;
  id?: string;
  category?: MemoryCategory;
  title?: string;
};

export function addMemory(_ctx: ToolContext) {
  return tool({
    description:
      "Save knowledge to persistent cross-session memory (~/.pensar/memories/). Check list_memories first to avoid duplicates. Categories: app, framework, general.",
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
