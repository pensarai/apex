import { tool } from "ai";
import { z } from "zod";
import type { ToolContext } from "./types";
import {
  listTasks as coreListTasks,
  getTaskSummary,
  type TaskStatus,
} from "../../../tasks";

const listTasksInputSchema = z.object({
  status: z
    .enum(["pending", "in_progress", "completed", "failed"])
    .optional()
    .describe("Filter by status. Omit to list all tasks."),
});

type ListTasksResult = {
  success: boolean;
  error?: string;
  tasks: Array<{
    id: number;
    subject: string;
    status: string;
    objective: string;
    technique: string;
    result?: string;
  }>;
  summary: {
    total: number;
    pending: number;
    in_progress: number;
    completed: number;
    failed: number;
  };
};

export function listTasksTool(ctx: ToolContext) {
  return tool({
    description: `List your testing tasks with status summaries.

Call this to check coverage:
- BEFORE calling response — verify all tasks are completed or failed (zero pending/in_progress)
- Mid-run to see what's remaining and decide what to work on next
- After a failure to assess which alternative techniques are available

Returns tasks sorted by ID with per-status counts.`,
    inputSchema: listTasksInputSchema,
    execute: async ({ status }): Promise<ListTasksResult> => {
      if (!ctx.tasksDir) {
        return {
          success: false,
          error: "Task system not available — tasksDir not configured",
          tasks: [],
          summary: {
            total: 0,
            pending: 0,
            in_progress: 0,
            completed: 0,
            failed: 0,
          },
        };
      }

      try {
        // Load all tasks once, filter for display, derive summary from full set
        const allTasks = coreListTasks(ctx.tasksDir);
        const filtered = status
          ? allTasks.filter((t) => t.status === (status as TaskStatus))
          : allTasks;
        const summary = getTaskSummary(ctx.tasksDir, allTasks);

        return {
          success: true,
          tasks: filtered.map((t) => ({
            id: t.id,
            subject: t.subject,
            status: t.status,
            objective: t.objective,
            technique: t.technique,
            result: t.result,
          })),
          summary,
        };
      } catch (err: unknown) {
        return {
          success: false,
          error: err instanceof Error ? err.message : String(err),
          tasks: [],
          summary: {
            total: 0,
            pending: 0,
            in_progress: 0,
            completed: 0,
            failed: 0,
          },
        };
      }
    },
  });
}
