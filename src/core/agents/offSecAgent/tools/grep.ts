import { spawn } from "node:child_process";
import { tool } from "ai";
import { z } from "zod";
import type { ToolContext } from "./types";

// Producer bound: accumulation stops once this many characters are buffered —
// results are never collected unbounded and sliced afterwards.
const MAX_OUTPUT_CHARS = 50_000;
// One chunk of slack past the cap before the child is killed, so the cap
// boundary itself is captured exactly.
const KILL_SLACK_CHARS = 8_192;
const GREP_TIMEOUT_MS = 30_000;

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
  /** Exact only for a complete run; omitted for every incomplete outcome. */
  matchCount?: number;
  command: string;
  /** True when the producer bound stopped collection before grep finished. */
  truncated?: boolean;
};

export function grep(ctx: ToolContext) {
  return tool({
    description: `Search file contents using grep.

Runs grep with the given pattern and optional flags. When searching a
directory, -r (recursive) is included automatically unless you explicitly
provide flags that already contain it.

USEFUL FLAG COMBINATIONS:
  -rn           recursive + line numbers (default for dirs)
  -rni          recursive + line numbers + case-insensitive
  -rl           recursive, file names only
  -E            extended regex
  -P            Perl-compatible regex
  -C 3          show 3 lines of context around matches
  --include="*.js"  restrict to certain file types

Output is capped at ${MAX_OUTPUT_CHARS} characters at the producer — a search
that exceeds it reports truncated=true and an approximate window instead of a
match count. Narrow the search with flags or a more specific directory.`,
    inputSchema: grepInputSchema,
    execute: async ({ pattern, directory, flags }): Promise<GrepResult> => {
      if (ctx.abortSignal?.aborted) {
        return {
          success: false,
          error: "Grep aborted by user",
          output: "",
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
        let stdoutTruncated = false;
        let stderrTruncated = false;
        let killedForCap = false;
        let killedByTimeout = false;
        let resolved = false;

        // Wire up abort signal — clean up in safeResolve to cover all exit paths
        let abortCleanup: (() => void) | undefined;
        if (ctx.abortSignal) {
          const abortHandler = () => child.kill("SIGTERM");
          ctx.abortSignal.addEventListener("abort", abortHandler, {
            once: true,
          });
          abortCleanup = () =>
            ctx.abortSignal?.removeEventListener("abort", abortHandler);
        }

        const safeResolve = (result: GrepResult) => {
          if (resolved) return;
          resolved = true;
          clearTimeout(timeout);
          abortCleanup?.();
          resolve(result);
        };

        const timeout = setTimeout(() => {
          killedByTimeout = true;
          child.kill("SIGTERM");
        }, GREP_TIMEOUT_MS);

        // Accumulation is bounded at the producer: once past the cap the
        // stream is destroyed (grep SIGPIPEs) instead of buffering forever.
        child.stdout.on("data", (data) => {
          if (stdoutTruncated) return;
          const chunk = data.toString();
          if (stdout.length + chunk.length > MAX_OUTPUT_CHARS) {
            stdout += chunk.slice(0, MAX_OUTPUT_CHARS - stdout.length);
            stdoutTruncated = true;
            killedForCap = true;
            child.stdout.destroy();
            child.kill("SIGTERM");
            return;
          }
          stdout += chunk;
        });

        child.stderr.on("data", (data) => {
          if (stderrTruncated) return;
          const chunk = data.toString();
          if (stderr.length + chunk.length > KILL_SLACK_CHARS) {
            stderr += chunk.slice(0, KILL_SLACK_CHARS - stderr.length);
            stderrTruncated = true;
            return;
          }
          stderr += chunk;
        });

        child.on("close", (code) => {
          const killedByAbort = ctx.abortSignal?.aborted === true;
          const interrupted = killedForCap || killedByTimeout || killedByAbort;
          // grep exits 1 with no stderr only when it genuinely found nothing.
          const noMatch = !interrupted && code === 1 && stderr === "";

          const output = killedForCap
            ? `${stdout}\n\n(truncated at ${MAX_OUTPUT_CHARS} characters — narrow your search; match count omitted because the full result was not captured)`
            : interrupted
              ? stdout
              : noMatch || (code === 0 && stdout === "")
                ? "(no matches)"
                : stdout;

          const error = killedByAbort
            ? "Grep aborted by user"
            : killedByTimeout
              ? `Grep timed out after ${GREP_TIMEOUT_MS / 1000}s — partial output only`
              : killedForCap
                ? `output capped at ${MAX_OUTPUT_CHARS} characters before grep finished`
                : noMatch || code === 0
                  ? ""
                  : stderr || `Exit code: ${code}`;

          safeResolve({
            // An interrupted or failed search is never a clean success, and
            // its (possibly empty) output is partial evidence, not a verdict.
            success: !interrupted && (code === 0 || noMatch),
            error,
            output,
            // An exact count needs a complete run — omitted for every
            // incomplete or nonzero-error outcome.
            ...(interrupted || (code !== 0 && !noMatch)
              ? {}
              : {
                  matchCount: stdout ? stdout.trimEnd().split("\n").length : 0,
                }),
            command,
            ...(interrupted ? { truncated: true } : {}),
          });
        });

        child.on("error", (err) => {
          safeResolve({
            success: false,
            error: err.message,
            output: "",
            command,
          });
        });
      });
    },
  });
}
