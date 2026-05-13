import { isAbsolute, relative } from "node:path";
import { tool } from "ai";
import { z } from "zod";
import {
  readWhiteboxArtifact as loadWhiteboxSessionArtifact,
  pollWhiteboxJob as pollJob,
  readWhiteboxJobLog,
  resolvePathWithinCodebaseRoot,
  resolveWhiteboxCodebaseRoot,
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
harnesses; do not modify the target repo unless the operator approved it.
Network scope constraints apply to hostnames in the command string; local shell
execution is not sandboxed.`,
    inputSchema: z.object({
      command: z.string().describe("Shell command to run"),
      cwd: z
        .string()
        .optional()
        .describe(
          "Working directory. Defaults to session.config.codebasePath or agent working directory; must stay under the configured codebase root.",
        ),
      timeoutSeconds: z
        .number()
        .int()
        .min(1)
        .max(86_400)
        .optional()
        .describe("Hard timeout in seconds. Defaults to 300, max 86400."),
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

      const codebaseRoot = resolveWhiteboxCodebaseRoot({
        agentCwd: ctx.agentCwd,
        codebasePath: ctx.session.config?.codebasePath,
      });
      let rootPath: string;
      try {
        rootPath = cwd
          ? resolvePathWithinCodebaseRoot(codebaseRoot, cwd)
          : codebaseRoot;
      } catch (error) {
        return {
          success: false,
          summary: error instanceof Error ? error.message : String(error),
          artifactPaths: [],
          nextActions: ["Use cwd inside the configured codebase root."],
          recovery:
            "Paths are constrained to session.config.codebasePath (or agent cwd).",
        };
      }

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
          `Read logs with read_whitebox_artifact using path: ${logPath}`,
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
      const record = pollJob(jobId, ctx.session.id);
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
            : [`Read logs with read_whitebox_artifact using path: ${logPath}`],
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
      const record = stopJob(jobId, ctx.session.id);
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
          `Read logs with read_whitebox_artifact using path: ${logPath}`,
        ],
        truncated: false,
      };
    },
  });
}

function normalizeArtifactRelativePath(
  ctx: ToolContext,
  userPath: string,
): string {
  if (isAbsolute(userPath)) {
    const rel = relative(ctx.session.rootPath, userPath);
    if (rel.startsWith("..") || rel === ".." || isAbsolute(rel)) {
      throw new Error("Artifact path must be inside the session directory.");
    }
    return rel.replace(/\\/g, "/");
  }
  return userPath.replace(/\\/g, "/");
}

export function readWhiteboxArtifact(ctx: ToolContext) {
  return tool({
    description: `Read a whitebox artifact file under the session (logs/whitebox/ or scratchpad/whitebox/), or legacy job logs by job id.

Prefer \`path\` from tool results (e.g. scan artifacts, code-query output, job log paths).`,
    inputSchema: z.object({
      path: z
        .string()
        .optional()
        .describe(
          "Session-relative path, e.g. logs/whitebox/....txt or scratchpad/whitebox/....txt",
        ),
      jobId: z
        .string()
        .optional()
        .describe("Legacy: read a job log by id when path is unknown"),
      toolCallDescription: z
        .string()
        .describe("A concise description of what you are reading"),
    }),
    execute: async ({ path, jobId }) => {
      if (path) {
        try {
          const relativePath = normalizeArtifactRelativePath(ctx, path);
          const loaded = await loadWhiteboxSessionArtifact({
            session: ctx.session,
            path: relativePath,
          });
          const display = displayPath(ctx, loaded.absolutePath);
          return {
            success: true,
            summary: `Read whitebox artifact ${display}.`,
            data: {
              content: loaded.content,
              truncated: loaded.truncated,
              path: display,
            },
            artifactPaths: [display],
            nextActions: [
              "If truncated, narrow reads or split analysis across smaller ranges.",
            ],
            truncated: loaded.truncated,
          };
        } catch (error) {
          return {
            success: false,
            summary:
              error instanceof Error
                ? error.message
                : String(error ?? "read failed"),
            artifactPaths: [],
            nextActions: [
              "Use artifact paths returned by profile_codebase, run_code_query, run_whitebox_scan, or job tools.",
            ],
            recovery:
              "Only logs/whitebox/ and scratchpad/whitebox/ files are readable via this tool.",
          };
        }
      }

      if (jobId) {
        const result = readWhiteboxJobLog(jobId, ctx.session.id);
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
            "Prefer passing logs/whitebox/... path directly next time.",
          ],
          truncated: result.truncated,
        };
      }

      return {
        success: false,
        summary: "Provide path (preferred) or jobId for legacy job logs.",
        artifactPaths: [],
        nextActions: ["Pass the artifact path returned by a whitebox tool."],
        recovery: undefined,
      };
    },
  });
}
