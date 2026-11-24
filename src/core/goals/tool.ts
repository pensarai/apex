import { hasToolCall, tool } from "ai";
import { z } from "zod";

export const UPDATE_GOAL_TOOL_NAME = "update_goal";

export const updateGoalInputSchema = z.object({
  status: z.enum(["complete", "blocked"]),
  summary: z
    .string()
    .min(1)
    .max(4_000)
    .describe(
      "For complete: what was done. For blocked: what blocks the goal and what would unblock it.",
    ),
  evidence: z
    .array(
      z.object({
        tool: z.string().min(1).describe("Name of the tool that was called"),
        quote: z
          .string()
          .min(1)
          .max(500)
          .describe("A short exact quote from that tool call's output"),
      }),
    )
    .max(10)
    .default([])
    .describe(
      "Required for complete: the tool results that prove the goal is met, from this goal's turns.",
    ),
});
export type EvidenceRef = UpdateGoalInput["evidence"][number];
export type UpdateGoalInput = z.infer<typeof updateGoalInputSchema>;

export function createUpdateGoalTool() {
  return tool({
    description:
      "Mark the active goal complete (with evidence) or blocked. Ends this turn; the harness checks the claim afterwards.",
    inputSchema: updateGoalInputSchema,
    execute: async () => ({
      recorded: true,
      note: "Recorded. End your turn now; the harness checks the claim.",
    }),
  });
}

export const goalStopCondition = hasToolCall(UPDATE_GOAL_TOOL_NAME);
