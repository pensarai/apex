import { tool } from "ai";
import { z } from "zod";
import { getMemory as coreGetMemory, type Memory } from "../../../memory";
import type { ToolContext } from "./types";

export const getMemoryInputSchema = z.object({
  id: z.string().describe("The unique memory id (returned by list_memories)"),
  toolCallDescription: z
    .string()
    .describe(
      "A concise, human-readable description of what this tool call is doing (e.g., 'Retrieving SQL injection cheatsheet')",
    ),
});

export type GetMemoryInput = z.infer<typeof getMemoryInputSchema>;

export type GetMemoryResult = {
  success: boolean;
  error: string;
  memory: Memory | null;
};

export function getMemory(_ctx: ToolContext) {
  return tool({
    description: `Retrieve the full content of a memory by its id.

Use list_memories first to discover available memory ids, then call this tool
to fetch the complete content of a specific memory.`,
    inputSchema: getMemoryInputSchema,
    execute: async ({ id }): Promise<GetMemoryResult> => {
      try {
        const memory = await coreGetMemory(id);
        if (!memory) {
          return {
            success: false,
            error: `Memory not found: ${id}`,
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
