import { tool } from "ai";
import { z } from "zod";
import { createLogger } from "../../../logger/structured";
import { planFilePath, readPlan } from "../../../plan";
import { scopedLogger } from "../../../util/lazyLogger";
import type { ToolContext } from "./types";

const log = scopedLogger(() => createLogger("submit_plan"));

const submitPlanInputSchema = z.object({
  toolCallDescription: z
    .string()
    .describe(
      "A concise, human-readable description of what this tool call is doing (e.g., 'Submitting pentest plan for operator review')",
    ),
});

type SubmitPlanResult = {
  success: boolean;
  error: string;
  path: string;
};

export function submitPlan(ctx: ToolContext & { subagentId?: string }) {
  return tool({
    description: `Submit the pentest plan for operator review and approval.

Call this tool AFTER you have written the plan via write_plan. It reads the plan
from disk and presents it to the operator for approval. The operator can approve,
reject (sending you back to refine), or edit the plan before approving.

Only call this when the plan is complete and ready for review.`,
    inputSchema: submitPlanInputSchema,
    execute: async (): Promise<SubmitPlanResult> => {
      const scopeId = ctx.planSubagentId ?? ctx.subagentId;
      const planPath = planFilePath(ctx.session.rootPath, scopeId);
      log.debug(`enter: path=${planPath}`);
      const plan = readPlan(ctx.session.rootPath, scopeId);
      if (!plan?.trim()) {
        return {
          success: false,
          error:
            "Plan file not found or empty. Write the plan first using write_plan.",
          path: planPath,
        };
      }
      log.debug(`done: planLen=${plan.length}`);
      return { success: true, error: "", path: planPath };
    },
  });
}
