import { tool } from "ai";
import { z } from "zod";
import { spawn } from "child_process";
import type { ToolContext } from "./types";

export const grepInputSchema = z.object({
  pattern: z.string().describe("The pattern to search for"),
  directory: z
    .string()
    .optional()
    .describe(
      "Directory or file path to search in (defaults to current working directory)",
    ),
  flags: z
    .string()
    .optional()
    .describe(
      'Additional grep flags (e.g. "-rn", "-i", "-l", "-E"). -r (recursive) is added by default when searching a directory.',
    ),
});

export type GrepInput = z.infer<typeof grepInputSchema>;

export type GrepResult = {
  success: boolean;
  error: string;
  output: string;
  matchCount: number;
  command: string;
};

export function grep(ctx: ToolContext) {
  return tool({
    description:
      "Search file contents by regex pattern. Recursive by default for directories. Output capped at 50K chars.",
    inputSchema: grepInputSchema,
    execute: async ({ pattern, directory, flags }): Promise<GrepResult> => {
      if (ctx.abortSignal?.aborted) {
        return {
          success: false,
          error: "Grep aborted by user",
          output: "",
          matchCount: 0,
          command: "",
        };
      }

      const dir = directory || ".";
      const cwd = ctx.agentCwd;
      const userFlags = flags ? flags.trim().split(/\s+/) : [];

      // Add -r by default when the user hasn't specified it and we're targeting a directory
      const hasRecursive = userFlags.some(
        (f) => /^-[a-zA-Z]*r[a-zA-Z]*$/.test(f) || f === "--recursive",
      );
      const defaultFlags = hasRecursive ? [] : ["-r"];

      const args = [...defaultFlags, ...userFlags, "--", pattern, dir];
      const command = `grep ${args.join(" ")}`;

      return new Promise((resolve) => {
        const child = spawn("grep", args, {
          cwd,
          stdio: ["ignore", "pipe", "pipe"],
        });

        let stdout = "";
        let stderr = "";
        let resolved = false;

        // Wire up abort signal — clean up in safeResolve to cover all exit paths
        let abortCleanup: (() => void) | undefined;
        if (ctx.abortSignal) {
          const abortHandler = () => child.kill("SIGTERM");
          ctx.abortSignal.addEventListener("abort", abortHandler, {
            once: true,
          });
          abortCleanup = () =>
            ctx.abortSignal!.removeEventListener("abort", abortHandler);
        }

        const safeResolve = (result: GrepResult) => {
          if (resolved) return;
          resolved = true;
          clearTimeout(timeout);
          abortCleanup?.();
          resolve(result);
        };

        const timeout = setTimeout(() => {
          child.kill("SIGTERM");
        }, 30_000);

        child.stdout.on("data", (data) => {
          stdout += data.toString();
        });

        child.stderr.on("data", (data) => {
          stderr += data.toString();
        });

        child.on("close", (code) => {
          // grep exits 1 when no matches — that's not an error
          const noMatch = code === 1 && stderr === "";
          const matchCount = stdout ? stdout.trimEnd().split("\n").length : 0;

          const truncated = stdout.length > 50_000;
          const output = truncated
            ? `${stdout.substring(0, 50_000)}\n\n(truncated — narrow your search)`
            : stdout || "(no matches)";

          safeResolve({
            success: code === 0 || noMatch,
            error: noMatch || code === 0 ? "" : stderr || `Exit code: ${code}`,
            output,
            matchCount,
            command,
          });
        });

        child.on("error", (err) => {
          safeResolve({
            success: false,
            error: err.message,
            output: "",
            matchCount: 0,
            command,
          });
        });
      });
    },
  });
}
