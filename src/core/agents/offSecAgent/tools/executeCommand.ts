import { tool } from "ai";
import { z } from "zod";
import { join } from "path";
import { writeFileSync, mkdirSync, existsSync } from "fs";
import type { ToolContext } from "./types";

const MAX_INLINE = 10_000;
const MS_TIMEOUT_THRESHOLD = 10_000;

export const executeCommandInputSchema = z.object({
  command: z.string().describe("The shell command to execute"),
  timeout: z
    .number()
    .optional()
    .describe(
      "Timeout in seconds. If omitted, the command runs until completion or abort.",
    ),
});

export type ExecuteCommandInput = z.infer<typeof executeCommandInputSchema>;

export type ExecuteCommandResult = {
  success: boolean;
  error: string;
  stdout: string;
  stderr: string;
  command: string;
  outputFile?: string;
};

/**
 * Defensively normalize obviously-millisecond timeout values into seconds.
 *
 * The tool contract is seconds, but models sometimes emit JavaScript-style
 * millisecond values like 30000 or 120000. Without normalization, those become
 * multi-hour hangs instead of 30s / 120s command limits.
 */
export function normalizeExecuteCommandTimeout(
  timeout?: number,
): number | undefined {
  if (timeout == null || !Number.isFinite(timeout) || timeout <= 0) {
    return undefined;
  }

  if (timeout >= MS_TIMEOUT_THRESHOLD) {
    return Math.max(1, Math.ceil(timeout / 1_000));
  }

  return timeout;
}

/**
 * If `raw` exceeds the inline limit, save the full text to a file under
 * `{session.logsPath}/cmd-output/` and return truncated text + file path.
 * Otherwise return the text as-is with no file.
 */
function maybeSaveFullOutput(
  raw: string,
  ctx: ToolContext,
): { text: string; file?: string } {
  if (raw.length <= MAX_INLINE) {
    return { text: raw || "(no output)" };
  }

  const outputDir = join(ctx.session.logsPath, "cmd-output");
  if (!existsSync(outputDir)) {
    mkdirSync(outputDir, { recursive: true });
  }

  const ts = new Date().toISOString().replace(/[:.]/g, "-");
  const filename = `output-${ts}.txt`;
  const filePath = join(outputDir, filename);

  try {
    writeFileSync(filePath, raw);
  } catch {
    return {
      text: `${raw.substring(0, MAX_INLINE)}...\n\n(truncated — failed to save full output to file)`,
    };
  }

  const truncated = raw.substring(0, MAX_INLINE);
  return {
    text: `${truncated}...\n\n(truncated — full output saved to ${filePath}). Use read_file or grep to analyze.`,
    file: filePath,
  };
}

export function executeCommand(ctx: ToolContext) {
  return tool({
    description:
      "Run a shell command. Shell is persistent across calls (env, cwd, background processes survive). Timeout is in SECONDS (not ms). Returns stdout, stderr, and exit status.",
    inputSchema: executeCommandInputSchema,
    execute: async ({ command, timeout }): Promise<ExecuteCommandResult> => {
      if (ctx.abortSignal?.aborted) {
        return {
          success: false,
          error: "Command aborted by user",
          stdout: "",
          stderr: "",
          command,
        };
      }

      // Sandbox mode: route execution through the sandbox
      if (ctx.sandbox) {
        try {
          const ssmOpts: { timeout?: number } = {};
          const normalizedTimeout = normalizeExecuteCommandTimeout(timeout);
          if (normalizedTimeout != null) {
            ssmOpts.timeout = normalizedTimeout;
          }
          const result = await ctx.sandbox.execute(command, ssmOpts);
          const { text: stdout, file: outputFile } = maybeSaveFullOutput(
            result.stdout,
            ctx,
          );
          return {
            success: result.success,
            error: !result.success ? result.stderr || "Command failed" : "",
            stdout,
            stderr: result.stderr || "",
            command,
            outputFile,
          };
        } catch (error: unknown) {
          const msg = error instanceof Error ? error.message : String(error);
          return {
            success: false,
            error: msg,
            stdout: "",
            stderr: msg,
            command,
          };
        }
      }

      // Local mode: use the persistent shell
      if (ctx.persistentShell) {
        try {
          const normalizedTimeout = normalizeExecuteCommandTimeout(timeout);
          const result = await ctx.persistentShell.execute(
            command,
            normalizedTimeout,
            ctx.onCommandOutput,
            ctx.abortSignal,
          );
          const { text: stdout, file: outputFile } = maybeSaveFullOutput(
            result.stdout,
            ctx,
          );
          return {
            success: result.exitCode === 0,
            error:
              result.exitCode === 124
                ? "Command timed out"
                : result.exitCode !== 0
                  ? `Exit code: ${result.exitCode}`
                  : "",
            stdout,
            stderr: result.stderr,
            command,
            outputFile,
          };
        } catch (error: unknown) {
          const msg = error instanceof Error ? error.message : String(error);
          return {
            success: false,
            error: msg,
            stdout: "",
            stderr: msg,
            command,
          };
        }
      }

      return {
        success: false,
        error: "No shell or sandbox available",
        stdout: "",
        stderr: "",
        command,
      };
    },
  });
}
