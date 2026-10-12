import { tool } from "ai";
import { z } from "zod";
import { resolveBackends } from "../../../tools/backends/resolve";
import type { GlobResult } from "./globImpl";
import { MAX_RESULTS } from "./globImpl";
import type { ToolContext } from "./types";

export type { GlobResult };

const globInputSchema = z.object({
  pattern: z
    .string()
    .describe(
      'Relative glob pattern (e.g. "**/*.ts", "src/**/*.tsx", "**/package.json"). Supports *, ?, [...], {a,b}, and ** as full path segments. Absolute patterns and ".." segments are rejected.',
    ),
  path: z
    .string()
    .optional()
    .describe(
      "Directory to search from (absolute or relative to the agent cwd). Defaults to agent cwd.",
    ),
  toolCallDescription: z
    .string()
    .describe(
      "A concise, human-readable description of what this tool call is doing (e.g., 'Find all TypeScript source files')",
    ),
});

export function globFiles(ctx: ToolContext) {
  return tool({
    description: `Find files by glob pattern under the agent working directory.

Examples:
- "**/*.ts" — all TypeScript files
- "src/**/*.{ts,tsx}" — sources under src/
- "**/package.json" — package manifests

Patterns are relative to the search root; absolute patterns and ".." segments
are rejected. Supports *, ?, [...], {a,b}, and ** as full path segments.

Skips common junk directories (node_modules, .git, dist, build, .next,
coverage, venv). Hidden path segments must be explicitly named in the pattern.
Results are capped at ${MAX_RESULTS}; narrow the
pattern if truncated.`,
    inputSchema: globInputSchema,
    execute: async ({ pattern, path }): Promise<GlobResult> => {
      const { fs } = resolveBackends(ctx);
      return fs.glob(pattern, { path });
    },
  });
}
