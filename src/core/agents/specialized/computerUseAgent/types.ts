import { z } from "zod";
import type { SpecializedAgentInput } from "../../offSecAgent";

/**
 * Structured result returned by the computer-use agent via the `response` tool.
 */
export const ComputerUseResultSchema = z.object({
  status: z
    .enum(["completed", "failed"])
    .describe("Whether the desktop objective was accomplished"),
  summary: z
    .string()
    .describe(
      "What was done on the desktop and the observed final state (from screenshots)",
    ),
});

export type ComputerUseResult = z.infer<typeof ComputerUseResultSchema>;

/**
 * Input for the {@link ComputerUseAgent} constructor.
 */
export interface ComputerUseAgentInput extends SpecializedAgentInput {
  /** The specific objective to accomplish on the desktop. */
  objective: string;

  /** Additional context about the target application or desktop state. */
  context?: string;
}
