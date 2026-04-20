import { tool } from "ai";
import { z } from "zod";
import type { ToolContext } from "./types";
import { updateTask as coreUpdateTask } from "../../../tasks";

const updateTaskInputSchema = z.object({
  taskId: z.number().describe("The task ID to update"),
  status: z
    .enum(["in_progress", "completed", "failed"])
    .describe("New status for the task"),
  result: z
    .string()
    .optional()
    .describe(
      "Outcome description — what was found or why the technique failed",
    ),
  observation: z
    .string()
    .optional()
    .describe("Intermediate observations or notes from testing"),
});

type UpdateTaskResult = {
  success: boolean;
  error?: string;
  task?: {
    id: number;
    subject: string;
    status: string;
    objective: string;
    technique: string;
    result?: string;
  };
};

export function updateTask(ctx: ToolContext) {
  return tool({
    description: `Update a task's status and record results.

Status transitions:
- "in_progress" — Set when you START testing a task. Pick one pending task at a time.
- "completed" — Set when testing is done: vulnerability found and documented via document_vulnerability, OR conclusively determined the endpoint is not vulnerable to this technique.
- "failed" — Set when the technique didn't work: rate limited, blocked by WAF, dead end, or approach not applicable. Then create a NEW task with an alternative technique.

Always include a result or observation explaining the outcome.`,
    inputSchema: updateTaskInputSchema,
    execute: async ({
      taskId,
      status,
      result,
      observation,
    }): Promise<UpdateTaskResult> => {
      if (!ctx.tasksDir) {
        return {
          success: false,
          error: "Task system not available — tasksDir not configured",
        };
      }

      try {
        const task = coreUpdateTask(ctx.tasksDir, taskId, {
          status,
          result,
          observation,
        });

        if (!task) {
          return {
            success: false,
            error: `Task ${taskId} not found`,
          };
        }

        // Record task lifecycle event in trace.jsonl
        ctx.traceWriter?.appendTaskRecord({
          action: "updated",
          taskId: task.id,
          data: {
            subject: task.subject,
            status: task.status,
            objective: task.objective,
            technique: task.technique,
            result: task.result,
            observation: task.observation,
          },
        });

        return {
          success: true,
          task: {
            id: task.id,
            subject: task.subject,
            status: task.status,
            objective: task.objective,
            technique: task.technique,
            result: task.result,
          },
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
