import { tool } from "ai";
import { z } from "zod";
import { searchMemories } from "../../../memory";
import type { ToolContext } from "./types";
import { TOOL_OUTPUT_MAX_BYTES } from "./toolOutput";

export function searchKnowledge(ctx: ToolContext) {
  return tool({
    description: `Search workspace knowledge by meaning. Returns a few short snippets, not the whole store. Use get_memory with the id when you need the full entry.`,
    inputSchema: z.object({
      query: z.string().min(1).max(500),
      toolCallDescription: z.string(),
    }),
    execute: async ({ query }, { toolCallId }) => {
      const hits = await searchMemories(
        query,
        undefined,
        { sessionId: ctx.session.id, toolCallId },
      );
      const payload = { success: true, hits };
      const json = JSON.stringify(payload);
      if (Buffer.byteLength(json) <= TOOL_OUTPUT_MAX_BYTES) return payload;
      return {
        success: true,
        truncated: true,
        hits: hits.slice(0, 3),
      };
    },
  });
}
