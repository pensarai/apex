import { tool } from "ai";
import { isAbsolute, relative, resolve } from "path";
import { z } from "zod";
import {
  pollWhiteboxJob as pollJob,
  readWhiteboxJobLog,
  startWhiteboxJob as startJob,
  stopWhiteboxJob as stopJob,
} from "../../../whitebox";
import { assertCommandInScope, ScopeViolationError } from "./scopeGuard";
import type { ToolContext } from "./types";

function displayPath(ctx: ToolContext, path: string): string {
  return path.startsWith(ctx.session.rootPath)
    ? relative(ctx.session.rootPath, path)
    : path;
}

export function startWhiteboxJob(ctx: ToolContext) {
  return tool({
    description: `Start a bounded whitebox job such as a local build, server, sanitizer run, scanner, or microfuzzer.

Use this for long-running work that needs polling and logs. Prefer scratch-space
harnesses; do not modify the target repo unless the operator approved it.`,
    inputSchema: z.object({
      command: z.string().describe("Shell command to run"),
      cwd: z
        .string()
        .optional()
        .describe(
          "Working directory. Defaults to session.config.codebasePath or agent working directory.",
        ),
      timeoutSeconds: z
        .number()
        .optional()
        .describe("Hard timeout in seconds. Defaults to 300."),
      name: z.string().optional().describe("Short job label for the log file"),
      toolCallDescription: z
        .string()
        .describe("A concise description of the whitebox job"),
    }),
    execute: async ({ command, cwd, timeoutSeconds = 300, name }) => {
      try {
        assertCommandInScope(command, ctx);
      } catch (error) {
        if (error instanceof ScopeViolationError) {
          return {
            success: false,
            summary: error.message,
            artifactPaths: [],
            nextActions: [
              "Adjust target scope or remove out-of-scope network activity.",
            ],
            recovery: "Whitebox jobs still honor network scope constraints.",
          };
        }
        throw error;
      }

      const rootPath = cwd
        ? isAbsolute(cwd)
          ? cwd
          : resolve(ctx.agentCwd, cwd)
        : (ctx.session.config?.codebasePath ?? ctx.agentCwd);
      const record = startJob({
        session: ctx.session,
        command,
        cwd: rootPath,
        timeoutSeconds,
        name,
      });
      const logPath = displayPath(ctx, record.logPath);
      return {
        success: true,
        summary: `Started whitebox job ${record.id}.`,
        data: { record: { ...record, logPath } },
        artifactPaths: [logPath],
        nextActions: [
          `Poll ${record.id} with poll_whitebox_job.`,
          "Read the log before drawing conclusions from crashes or scanner results.",
        ],
        truncated: false,
      };
    },
  });
}

export function pollWhiteboxJob(ctx: ToolContext) {
  return tool({
    description: "Poll a running or completed whitebox job by id.",
    inputSchema: z.object({
      jobId: z.string(),
      toolCallDescription: z.string().describe("A concise polling description"),
    }),
    execute: async ({ jobId }) => {
      const record = pollJob(jobId);
      if (!record) {
        return {
          success: false,
          summary: `Whitebox job not found: ${jobId}`,
          artifactPaths: [],
          nextActions: ["Check the job id from start_whitebox_job."],
          recovery:
            "Job records are in-process; restart-safe persistence is not guaranteed.",
        };
      }
      const logPath = displayPath(ctx, record.logPath);
      return {
        success: true,
        summary: `Whitebox job ${jobId} is ${record.status}.`,
        data: { record: { ...record, logPath } },
        artifactPaths: [logPath],
        nextActions:
          record.status === "running"
            ? ["Poll again later or stop the job if it is no longer useful."]
            : ["Read the job log and update related candidates."],
        truncated: false,
      };
    },
  });
}

export function stopWhiteboxJob(ctx: ToolContext) {
  return tool({
    description: "Stop a running whitebox job by id.",
    inputSchema: z.object({
      jobId: z.string(),
      toolCallDescription: z.string().describe("A concise stop description"),
    }),
    execute: async ({ jobId }) => {
      const record = stopJob(jobId);
      if (!record) {
        return {
          success: false,
          summary: `Whitebox job not found: ${jobId}`,
          artifactPaths: [],
          nextActions: ["Check the job id from start_whitebox_job."],
          recovery:
            "Job records are in-process; restart-safe persistence is not guaranteed.",
        };
      }
      const logPath = displayPath(ctx, record.logPath);
      return {
        success: true,
        summary: `Whitebox job ${jobId} is ${record.status}.`,
        data: { record: { ...record, logPath } },
        artifactPaths: [logPath],
        nextActions: [
          "Read the job log and preserve any useful artifact references.",
        ],
        truncated: false,
      };
    },
  });
}

export function readWhiteboxArtifact(ctx: ToolContext) {
  return tool({
    description:
      "Read the log for a whitebox job. Use this after poll_whitebox_job reports completion, failure, timeout, or a crash signal.",
    inputSchema: z.object({
      jobId: z.string(),
      toolCallDescription: z
        .string()
        .describe("A concise log-read description"),
    }),
    execute: async ({ jobId }) => {
      const result = readWhiteboxJobLog(jobId);
      if (!result.record) {
        return {
          success: false,
          summary: `Whitebox job not found: ${jobId}`,
          artifactPaths: [],
          nextActions: ["Check the job id from start_whitebox_job."],
          recovery:
            "Job records are in-process; restart-safe persistence is not guaranteed.",
        };
      }
      const logPath = displayPath(ctx, result.record.logPath);
      return {
        success: true,
        summary: `Read log for whitebox job ${jobId}.`,
        data: {
          record: { ...result.record, logPath },
          content: result.content,
        },
        artifactPaths: [logPath],
        nextActions: [
          "If the log shows a crash or exploitable behavior, attach it to a candidate.",
          "Minimize reproducers before documenting confirmed vulnerabilities.",
        ],
        truncated: result.truncated,
      };
    },
  });
}
