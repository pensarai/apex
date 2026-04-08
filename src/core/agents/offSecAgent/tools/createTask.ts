import { tool } from "ai";
import { z } from "zod";
import type { ToolContext } from "./types";
import { createTask as coreCreateTask } from "../../../tasks";

const createTaskInputSchema = z.object({
  subject: z
    .string()
    .describe(
      "Short subject line for the task (e.g., 'Test /api/users id param for UNION-based SQLi')",
    ),
  description: z
    .string()
    .describe(
      "Detailed description of what to test and how — include specific payloads, encoding strategies, or bypass techniques to try",
    ),
  objective: z
    .string()
    .describe(
      "The testing objective this task addresses (from your assigned objectives)",
    ),
  technique: z
    .string()
    .describe(
      "The specific attack technique (e.g., 'UNION-based SQL injection', 'reflected XSS via search parameter', 'time-based blind SQLi')",
    ),
  metadata: z
    .record(z.string(), z.unknown())
    .optional()
    .describe(
      "Optional metadata (e.g., { priority: 'high', endpoint: '/api/users', parameter: 'id' })",
    ),
});

type CreateTaskResult = {
  success: boolean;
  error?: string;
  task?: {
    id: number;
    subject: string;
    status: string;
    objective: string;
    technique: string;
  };
};

export function createTask(ctx: ToolContext) {
  return tool({
    description: `Create a testing task to track your work.

Decompose each objective into concrete, atomic testing tasks — one task per technique × endpoint combination. Tasks track what you've planned, what you're doing, and what's done.

Call this BEFORE you start testing to build your task list. You can also add tasks mid-run when you discover new attack vectors.

Examples of good tasks:
- "Test /api/users id parameter for error-based SQL injection"
- "Test /search q parameter for reflected XSS with event handler payloads"
- "Test /api/auth for JWT signature bypass via algorithm confusion"`,
    inputSchema: createTaskInputSchema,
    execute: async ({
      subject,
      description,
      objective,
      technique,
      metadata,
    }): Promise<CreateTaskResult> => {
      if (!ctx.tasksDir) {
        return {
          success: false,
          error: "Task system not available — tasksDir not configured",
        };
      }

      try {
        const task = coreCreateTask(ctx.tasksDir, {
          subject,
          description,
          objective,
          technique,
          metadata,
        });

        // Record task lifecycle event in trace.jsonl
        ctx.traceWriter?.appendTaskRecord({
          action: "created",
          taskId: task.id,
          data: {
            subject: task.subject,
            status: task.status,
            objective: task.objective,
            technique: task.technique,
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
