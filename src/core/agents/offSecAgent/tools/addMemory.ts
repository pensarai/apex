import { tool } from "ai";
import { z } from "zod";
import { addMemory as coreAddMemory } from "../../../memory";
import type { ToolContext } from "./types";

export const addMemoryInputSchema = z.object({
  title: z
    .string()
    .describe("Short, descriptive title for the memory (used to generate id)"),
  content: z.string().describe("Free-form text content to persist as a memory"),
  tags: z
    .array(z.string())
    .optional()
    .describe("Optional tags for categorisation and filtering"),
  toolCallDescription: z
    .string()
    .describe(
      "A concise, human-readable description of what this tool call is doing (e.g., 'Saving XSS payload pattern')",
    ),
});

export type AddMemoryInput = z.infer<typeof addMemoryInputSchema>;

export type AddMemoryResult = {
  success: boolean;
  error: string;
  id?: string;
  title?: string;
};

export function addMemory(_ctx: ToolContext) {
  return tool({
    description: `Save a piece of knowledge to persistent memory.

Memories are stored across sessions in ~/.pensar/memories/ and survive restarts.
Use this to record reusable techniques, target-specific notes, credential
patterns, useful payloads, or any information worth remembering for future
engagements.`,
    inputSchema: addMemoryInputSchema,
    execute: async ({ title, content, tags }): Promise<AddMemoryResult> => {
      try {
        const memory = await coreAddMemory({ title, content, tags });
        return {
          success: true,
          error: "",
          id: memory.id,
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
