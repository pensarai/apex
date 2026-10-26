import { tool } from "ai";
import { z } from "zod";
import { recordLearning as coreRecordLearning } from "../../../memory";
import type { ToolContext } from "./types";

const kinds = [
  "technique_worked",
  "technique_failed",
  "target_fact",
  "false_positive",
  "directive",
] as const;

export function recordLearning(ctx: ToolContext) {
  return tool({
    description: `Save one verified, reusable insight. A similar existing entry is reinforced instead of duplicated. Do not record guesses, and do not record secrets.`,
    inputSchema: z.object({
      kind: z.enum(kinds),
      title: z.string().min(1).max(200),
      content: z.string().min(1).max(4_000),
      toolCallDescription: z.string(),
    }),
    execute: async ({ kind, title, content }, { toolCallId }) => {
      const saved = await coreRecordLearning(
        { kind, title, content },
        { sessionId: ctx.session.id, toolCallId },
      );
      return { success: true, ...saved };
    },
  });
}
