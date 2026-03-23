import { tool } from "ai";
import { z } from "zod";
import {
  listMemories as coreListMemories,
  MEMORY_CATEGORIES,
  type MemorySummary,
} from "../../../memory";
import type { ToolContext } from "./types";

export const listMemoriesInputSchema = z.object({
  category: z
    .enum(MEMORY_CATEGORIES)
    .optional()
    .describe(
      'Filter by category: "app", "framework", or "general". ' +
        "Omit to list memories across all categories.",
    ),
  tag: z
    .string()
    .optional()
    .describe("Optional tag to filter memories by (exact match)"),
});

export type ListMemoriesInput = z.infer<typeof listMemoriesInputSchema>;

export type ListMemoriesResult = {
  success: boolean;
  error: string;
  memories: MemorySummary[];
  count: number;
};

export function listMemories(_ctx: ToolContext) {
  return tool({
    description:
      "List saved memories filtered by category/tag. Returns summaries (id, title, tags). Use get_memory for full content.",
    inputSchema: listMemoriesInputSchema,
    execute: async ({ category, tag }): Promise<ListMemoriesResult> => {
      try {
        const memories = await coreListMemories({ category, tag });
        return {
          success: true,
          error: "",
          memories,
          count: memories.length,
        };
      } catch (err: unknown) {
        return {
          success: false,
          error: err instanceof Error ? err.message : String(err),
          memories: [],
          count: 0,
        };
      }
    },
  });
}
