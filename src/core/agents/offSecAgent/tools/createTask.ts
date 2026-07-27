import { tool } from "ai";
import { z } from "zod";
import { createTask as coreCreateTask } from "../../../tasks";
import type { ToolContext } from "./types";

const createTaskInputSchema = z.object({
  subject: z
    .string()
    .describe(
      "Short subject line for the task (e.g., 'Apply parameterized query fix in login handler', 'Test /api/users id param for UNION-based SQLi')",
    ),
  description: z
    .string()
    .describe(
      "Detailed description of the work — for coding: what to change and how to verify; for testing: payloads, encoding strategies, or bypass techniques",
    ),
  objective: z
    .string()
    .optional()
    .describe(
      "Optional higher-level objective this task addresses (e.g. a pentest objective or 'Fix SQL injection in auth'). Defaults to the subject when omitted.",
    ),
  technique: z
    .string()
    .optional()
    .describe(
      "Optional technique or approach label (e.g. 'parameterized queries', 'UNION-based SQL injection'). Defaults to 'general' when omitted.",
    ),
  metadata: z
    .record(z.string(), z.unknown())
    .optional()
    .describe(
      "Optional metadata (e.g. { priority: 'high', file: 'src/auth.ts', endpoint: '/api/users' })",
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
    description: `Create a task to track your work.

Use tasks as a lightweight todo list: decompose the job into concrete, atomic steps, create them early, and update status as you go.

Works for both coding agents (patch/fix/verify steps) and pentest agents (technique × endpoint tests).

Call this BEFORE you start substantive work to build your task list. Add more mid-run when you discover extra work.

Examples of good tasks:
- "Read vulnerable login handler and related DB helpers"
- "Apply parameterized query fix in src/auth/login.ts"
- "Run lint, typecheck, and unit tests"
- "Test /api/users id parameter for error-based SQL injection"`,
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
          objective: objective ?? subject,
          technique: technique ?? "general",
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
