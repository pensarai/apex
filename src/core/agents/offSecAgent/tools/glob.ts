import { tool } from "ai";
import { z } from "zod";
import { CAPS } from "../../../tools/backends/helpers";
import { resolveBackends } from "../../../tools/backends/resolve";
import type { ToolContext } from "./types";

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

export function globFiles(ctx: ToolContext) {
  return tool({
    description: `Find files by glob pattern under the agent working directory.

Examples:
- "**/*.ts" — all TypeScript files
- "src/**/*.{ts,tsx}" — sources under src/
- "**/package.json" — package manifests

Skips common junk directories (node_modules, .git, dist, build, .next, coverage, venv).
Results are capped at ${CAPS.GLOB_MAX_RESULTS}; narrow the pattern if truncated.`,
    inputSchema: globInputSchema,
    execute: async ({ pattern, path }): Promise<GlobResult> => {
      const { fs } = resolveBackends(ctx);
      return fs.glob(pattern, { path });
    },
  });
}
