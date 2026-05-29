import { tool } from "ai";
import { spawn } from "node:child_process";
import { z } from "zod";
import type { ToolContext } from "./types";

const grepInputSchema = z.object({
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
  toolCallDescription: z
    .string()
    .describe(
      "A concise, human-readable description of what this tool call is doing (e.g., 'Searching for password hashes in config files')",
    ),
});

type GrepInput = z.infer<typeof grepInputSchema>;

export type GrepResult = {
  success: boolean;
  error: string;
  output: string;
  matchCount: number;
  command: string;
};

export function grep(ctx: ToolContext) {
  return tool({
    description: `Search file contents using grep.

Runs grep with the given pattern and optional flags. When searching a
directory, -r (recursive) is included automatically unless you explicitly
provide flags that already contain it.

USEFUL FLAG COMBOS:
  -rn           recursive + line numbers (default for dirs)
  -rni          recursive + line numbers + case-insensitive
  -rl           recursive, file names only
  -E            extended regex
  -P            Perl-compatible regex
  -C 3          show 3 lines of context around matches
  --include="*.js"  restrict to certain file types

Output is capped at 50 000 characters to avoid context overflow — narrow your
search with flags or a more specific directory if results are truncated.`,
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
