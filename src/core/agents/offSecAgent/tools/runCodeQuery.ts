import { tool } from "ai";
import { spawn } from "child_process";
import { isAbsolute, resolve } from "path";
import { z } from "zod";
import { writeWhiteboxArtifact } from "../../../whitebox";
import type { ToolContext } from "./types";

const MAX_INLINE_MATCHES = 40;

const QueryEngineSchema = z.enum(["rg", "grep", "ast-grep", "comby"]);

type QueryResult = {
  engine: string;
  pattern: string;
  path: string;
  exitCode: number | null;
  matchCount: number;
  sample: string[];
  artifactPath?: string;
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
      return [pattern, "", targetPath];
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
}> {
  return new Promise((resolve) => {
    const child = spawn(
      input.engine,
      buildArgs(input.engine, input.pattern, input.targetPath),
      {
        cwd: input.cwd,
        stdio: ["ignore", "pipe", "pipe"],
      },
    );
    let stdout = "";
    let stderr = "";
    let settled = false;
    const timeout = setTimeout(
      () => child.kill("SIGTERM"),
      input.timeoutSeconds * 1000,
    );

    child.stdout.on("data", (data) => {
      stdout += data.toString();
    });
    child.stderr.on("data", (data) => {
      stderr += data.toString();
    });
    child.on("close", (code) => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      resolve({ stdout, stderr, exitCode: code });
    });
    child.on("error", (error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      resolve({ stdout, stderr: error.message, exitCode: null });
    });
  });
}

export function runCodeQuery(ctx: ToolContext) {
  return tool({
    description: `Run structured source-code searches for whitebox analysis.

Supports rg, grep, ast-grep, and comby when installed. Use batch queries for
sink-first sweeps. Returns counts, representative samples, and full artifacts
instead of flooding context with every match.`,
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
                "File or directory to search, relative to cwd by default",
              ),
          }),
        )
        .describe("Independent source-code queries to run"),
      cwd: z
        .string()
        .optional()
        .describe(
          "Repository root. Defaults to session.config.codebasePath or agent working directory.",
        ),
      timeoutSeconds: z.number().optional().describe("Per-query timeout"),
      toolCallDescription: z
        .string()
        .describe("A concise description of the code query"),
    }),
    execute: async ({ engine = "rg", queries, cwd, timeoutSeconds = 30 }) => {
      const rootPath = cwd
        ? isAbsolute(cwd)
          ? cwd
          : resolve(ctx.agentCwd, cwd)
        : (ctx.session.config?.codebasePath ?? ctx.agentCwd);

      const results: QueryResult[] = [];
      for (const query of queries) {
        const targetPath = query.path ?? ".";
        const output = await runSingleQuery({
          engine,
          pattern: query.pattern,
          cwd: rootPath,
          targetPath,
          timeoutSeconds,
        });
        const lines = output.stdout.split("\n").filter(Boolean);
        const artifact = await writeWhiteboxArtifact({
          session: ctx.session,
          type: "code-query",
          name: `${engine}-${query.pattern.slice(0, 40)}`,
          content:
            output.stdout +
            (output.stderr ? `\n\n[stderr]\n${output.stderr}` : ""),
          description: `${engine} query for ${query.pattern}`,
          extension: ".txt",
        });

        results.push({
          engine,
          pattern: query.pattern,
          path: targetPath,
          exitCode: output.exitCode,
          matchCount: lines.length,
          sample: lines.slice(0, MAX_INLINE_MATCHES),
          artifactPath: artifact.path,
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
