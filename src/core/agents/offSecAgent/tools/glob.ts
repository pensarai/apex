import { isAbsolute, relative, resolve } from "node:path";
import { tool } from "ai";
import { glob as globAsync } from "glob";
import { z } from "zod";
import type { ToolContext } from "./types";

const DEFAULT_IGNORE = [
  "**/node_modules/**",
  "**/.git/**",
  "**/dist/**",
  "**/build/**",
  "**/.next/**",
  "**/coverage/**",
  "**/__pycache__/**",
  "**/.venv/**",
  "**/venv/**",
];

const MAX_RESULTS = 200;

const globInputSchema = z.object({
  pattern: z
    .string()
    .describe(
      'Glob pattern to match files (e.g. "**/*.ts", "src/**/*.tsx", "**/package.json")',
    ),
  path: z
    .string()
    .optional()
    .describe(
      "Directory to search from (absolute or relative to agent cwd). Defaults to agent cwd.",
    ),
  toolCallDescription: z
    .string()
    .describe(
      "A concise, human-readable description of what this tool call is doing (e.g., 'Find all TypeScript source files')",
    ),
});

export type GlobResult = {
  success: boolean;
  error: string;
  files: string[];
  count: number;
  totalFound?: number;
  pattern: string;
  cwd: string;
};

/**
 * Resolve the search root and ensure it stays under agentCwd.
 * Throws when the resolved path escapes the agent working directory.
 */
export function resolveGlobRoot(agentCwd: string, path?: string): string {
  const root = path
    ? isAbsolute(path)
      ? path
      : resolve(agentCwd, path)
    : agentCwd;
  const rel = relative(agentCwd, root);
  if (rel.startsWith("..") || isAbsolute(rel)) {
    throw new Error(
      `Path escapes agent working directory: ${path ?? root}`,
    );
  }
  return root;
}

export function globFiles(ctx: ToolContext) {
  return tool({
    description: `Find files by glob pattern under the agent working directory.

Examples:
- "**/*.ts" — all TypeScript files
- "src/**/*.{ts,tsx}" — sources under src/
- "**/package.json" — package manifests

Skips common junk directories (node_modules, .git, dist, build, .next, coverage, venv).
Results are capped at ${MAX_RESULTS}; narrow the pattern if truncated.`,
    inputSchema: globInputSchema,
    execute: async ({ pattern, path }): Promise<GlobResult> => {
      let root: string;
      try {
        root = resolveGlobRoot(ctx.agentCwd, path);
      } catch (err: unknown) {
        return {
          success: false,
          error: err instanceof Error ? err.message : String(err),
          files: [],
          count: 0,
          pattern,
          cwd: ctx.agentCwd,
        };
      }

      try {
        if (ctx.sandbox) {
          // Sandbox: shell out to find matching paths via a bounded find/glob.
          // Use bash globstar when available; fall back to find + case filter.
          const escapedPattern = pattern.replace(/"/g, '\\"');
          const cmd = `shopt -s globstar nullglob 2>/dev/null; cd "${root}" && compgen -G "${escapedPattern}" | head -n ${MAX_RESULTS + 1}`;
          const result = await ctx.sandbox.execute(cmd, { timeout: 30 });
          const lines = result.stdout
            .split("\n")
            .map((l) => l.trim())
            .filter(Boolean);
          const truncated = lines.length > MAX_RESULTS;
          const files = lines.slice(0, MAX_RESULTS);
          return {
            success: true,
            error: truncated
              ? `Showing ${MAX_RESULTS} of at least ${lines.length} matches — narrow the pattern`
              : "",
            files,
            count: files.length,
            totalFound: truncated ? lines.length : undefined,
            pattern,
            cwd: root,
          };
        }

        const matches = await globAsync(pattern, {
          cwd: root,
          nodir: true,
          dot: false,
          ignore: DEFAULT_IGNORE,
          absolute: false,
        });

        const truncated = matches.length > MAX_RESULTS;
        const files = matches.slice(0, MAX_RESULTS).sort();

        return {
          success: true,
          error: truncated
            ? `Showing ${MAX_RESULTS} of ${matches.length} matches — narrow the pattern`
            : "",
          files,
          count: files.length,
          totalFound: truncated ? matches.length : undefined,
          pattern,
          cwd: root,
        };
      } catch (err: unknown) {
        return {
          success: false,
          error: err instanceof Error ? err.message : String(err),
          files: [],
          count: 0,
          pattern,
          cwd: root,
        };
      }
    },
  });
}
