import { tool } from "ai";
import { z } from "zod";
import {
  getMemory as coreGetMemory,
  MEMORY_CATEGORIES,
  type Memory,
} from "../../../memory";
import type { ToolContext } from "./types";

export const getMemoryInputSchema = z.object({
  category: z
    .enum(MEMORY_CATEGORIES)
    .describe(
      'The memory category: "app", "framework", or "general" (returned by list_memories)',
    ),
  id: z.string().describe("The unique memory id (returned by list_memories)"),
});

export type GetMemoryInput = z.infer<typeof getMemoryInputSchema>;

export type GetMemoryResult = {
  success: boolean;
  error: string;
  memory: Memory | null;
};

export function getMemory(_ctx: ToolContext) {
  return tool({
    description:
      "Retrieve full content of a memory by category and id. Use list_memories first to find available memories.",
    inputSchema: getMemoryInputSchema,
    execute: async ({ category, id }): Promise<GetMemoryResult> => {
      try {
        const memory = await coreGetMemory(category, id);
        if (!memory) {
          return {
            success: false,
            error: `Memory not found: ${category}/${id}`,
            memory: null,
          };
        }
        return {
          success: true,
          error: "",
          memory,
        };
      } catch (err: unknown) {
        return {
          success: false,
          error: err instanceof Error ? err.message : String(err),
          memory: null,
        };
      }
    },
  });
}
