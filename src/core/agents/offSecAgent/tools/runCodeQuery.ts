import { relative } from "node:path";
import { tool } from "ai";
import { z } from "zod";
import {
  resolvePathWithinCodebaseRoot,
  resolveWhiteboxCodebaseRoot,
  runSpawnBounded,
  writeWhiteboxArtifact,
} from "../../../whitebox";
import type { ToolContext } from "./types";

const MAX_INLINE_MATCHES = 40;
const MAX_QUERY_CAPTURE_BYTES = 2 * 1024 * 1024;

const QueryEngineSchema = z.enum(["rg", "grep", "ast-grep", "comby"]);

type QueryResult = {
  engine: string;
  pattern: string;
  path: string;
  exitCode: number | null;
  matchCount: number;
  sample: string[];
  artifactPath?: string;
  outputTruncated?: boolean;
  timedOut?: boolean;
  error?: string;
};

function buildArgs(
  engine: string,
  pattern: string,
  targetPath: string,
): string[] {
  switch (engine) {
    case "rg":
      return ["--line-number", "--no-heading", pattern, targetPath];
    case "ast-grep":
      return ["--pattern", pattern, targetPath];
    case "comby":
      return [pattern, "", "-match-only", targetPath];
    default:
      return ["-rn", "--", pattern, targetPath];
  }
}

async function runSingleQuery(input: {
  engine: string;
  pattern: string;
  cwd: string;
  targetPath: string;
  timeoutSeconds: number;
}): Promise<{
  stdout: string;
  stderr: string;
  exitCode: number | null;
  outputTruncated: boolean;
  timedOut: boolean;
}> {
  const argv = [
    input.engine,
    ...buildArgs(input.engine, input.pattern, input.targetPath),
  ];
  return runSpawnBounded({
    command: argv,
    cwd: input.cwd,
    timeoutSeconds: input.timeoutSeconds,
    maxTotalBytes: MAX_QUERY_CAPTURE_BYTES,
    detached: false,
  });
}

export function runCodeQuery(ctx: ToolContext) {
  return tool({
    description: `Run structured source-code searches for whitebox analysis.

Supports rg, grep, ast-grep, and comby when installed. Use batch queries for
sink-first sweeps. Returns counts, representative samples, and artifact paths
instead of flooding context with every match. Output size and runtime are bounded.`,
    inputSchema: z.object({
      engine: QueryEngineSchema.optional().default("rg"),
      queries: z
        .array(
          z.object({
            pattern: z.string().describe("Pattern or structural query"),
            path: z
              .string()
              .optional()
              .describe(
                "File or directory to search, relative to the query cwd (must stay under the codebase root).",
              ),
          }),
        )
        .min(1)
        .max(40)
        .describe("Independent source-code queries to run"),
      cwd: z
        .string()
        .optional()
        .describe(
          "Repository root for the query. Defaults to session.config.codebasePath or agent working directory; must stay under the configured codebase root.",
        ),
      timeoutSeconds: z
        .number()
        .int()
        .positive()
        .max(900)
        .optional()
        .describe("Per-query timeout in seconds (default 30, max 900)."),
      toolCallDescription: z
        .string()
        .describe("A concise description of the code query"),
    }),
    execute: async ({ engine = "rg", queries, cwd, timeoutSeconds = 30 }) => {
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
          data: { results: [] as QueryResult[] },
          artifactPaths: [],
          nextActions: [
            "Use cwd and query paths inside the configured codebase root.",
          ],
          recovery:
            "Relative cwd is resolved from agent cwd then constrained under the codebase root.",
        };
      }

      const results: QueryResult[] = [];
      for (const query of queries) {
        let targetPathForEngine = ".";
        try {
          const absTarget = resolvePathWithinCodebaseRoot(
            rootPath,
            query.path ?? ".",
          );
          targetPathForEngine = relative(rootPath, absTarget) || ".";
        } catch (error) {
          results.push({
            engine,
            pattern: query.pattern,
            path: query.path ?? ".",
            exitCode: null,
            matchCount: 0,
            sample: [],
            error: error instanceof Error ? error.message : String(error),
          });
          continue;
        }

        const output = await runSingleQuery({
          engine,
          pattern: query.pattern,
          cwd: rootPath,
          targetPath: targetPathForEngine,
          timeoutSeconds,
        });
        const lines = output.stdout.split("\n").filter(Boolean);
        const combined =
          output.stdout +
          (output.stderr ? `\n\n[stderr]\n${output.stderr}` : "");
        let artifactPath: string | undefined;
        if (
          combined.trim().length > 0 ||
          output.timedOut ||
          output.outputTruncated
        ) {
          const artifact = await writeWhiteboxArtifact({
            session: ctx.session,
            type: "code-query",
            name: `${engine}-${query.pattern.slice(0, 40)}`,
            content:
              combined +
              (output.outputTruncated
                ? "\n\n[apex] stdout/stderr truncated at byte cap.\n"
                : "") +
              (output.timedOut ? "\n[apex] query timed out.\n" : ""),
            description: `${engine} query for ${query.pattern}`,
            extension: ".txt",
          });
          artifactPath = artifact.path;
        }

        results.push({
          engine,
          pattern: query.pattern,
          path: targetPathForEngine,
          exitCode: output.exitCode,
          matchCount: lines.length,
          sample: lines.slice(0, MAX_INLINE_MATCHES),
          artifactPath,
          outputTruncated: output.outputTruncated,
          timedOut: output.timedOut,
          error:
            output.exitCode === 0 || output.exitCode === 1
              ? undefined
              : output.stderr || undefined,
        });
      }

      const matchCount = results.reduce(
        (sum, result) => sum + result.matchCount,
        0,
      );
      return {
        success: results.every((result) => !result.error),
        summary: `Ran ${results.length} ${engine} query(s), ${matchCount} match line(s).`,
        data: { results },
        artifactPaths: results
          .map((result) => result.artifactPath)
          .filter((path): path is string => Boolean(path)),
        nextActions: [
          "Read high-signal files around representative matches.",
          "Trace candidate sinks backward to attacker-controlled sources.",
          "Create or update whitebox candidates for plausible reachable issues.",
        ],
        truncated: results.some(
          (result) => result.matchCount > MAX_INLINE_MATCHES,
        ),
        recovery: results.some((result) => result.error)
          ? "If the engine is unavailable or pattern syntax failed, retry with engine=grep or a simpler pattern."
          : undefined,
      };
    },
  });
}
