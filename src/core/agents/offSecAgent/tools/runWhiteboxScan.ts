import { tool } from "ai";
import { isAbsolute, resolve } from "path";
import { z } from "zod";
import type { ScanKind } from "../../../whitebox";
import {
  profileCodebase,
  runScanAdapter,
  selectScanAdapters,
  writeWhiteboxArtifact,
} from "../../../whitebox";
import type { ToolContext } from "./types";

const ScanKindSchema = z.enum([
  "static",
  "secrets",
  "dependencies",
  "iac",
  "repo-intelligence",
  "fuzzing",
]);

export function runWhiteboxScan(ctx: ToolContext) {
  return tool({
    description: `Run installed whitebox security scanners with bounded output.

The tool detects applicable scanner adapters for the repository and normalizes
results into concise summaries plus artifact paths. Missing tools are reported
as recoverable conditions. Static results are candidates only; verify before
calling document_vulnerability.`,
    inputSchema: z.object({
      path: z
        .string()
        .optional()
        .describe(
          "Repository root to scan. Defaults to session.config.codebasePath or agent working directory.",
        ),
      kind: ScanKindSchema.optional().describe("Restrict scan family"),
      scannerIds: z
        .array(z.string())
        .optional()
        .describe("Specific adapter IDs to run, e.g. semgrep, gitleaks"),
      timeoutSeconds: z
        .number()
        .optional()
        .describe("Per-scanner timeout in seconds. Defaults to 120."),
      toolCallDescription: z
        .string()
        .describe("A concise description of the scan"),
    }),
    execute: async ({ path, kind, scannerIds, timeoutSeconds = 120 }) => {
      const rootPath = path
        ? isAbsolute(path)
          ? path
          : resolve(ctx.agentCwd, path)
        : (ctx.session.config?.codebasePath ?? ctx.agentCwd);

      try {
        const profile = await profileCodebase(rootPath);
        const adapters = selectScanAdapters({
          profile,
          kind: kind as ScanKind | undefined,
          scannerIds,
        });

        if (adapters.length === 0) {
          return {
            success: false,
            summary: "No applicable installed whitebox scanners found.",
            data: {
              requested: { kind, scannerIds },
              availableTools: profile.toolAvailability.filter(
                (tool) => tool.available,
              ),
            },
            artifactPaths: [],
            nextActions: [
              "Use query_whitebox_catalog for manual search patterns.",
              "Use run_code_query for targeted source searches.",
            ],
            recovery:
              "Install one of the relevant scanners or run a code-query pass instead.",
          };
        }

        const results = [];
        for (const adapter of adapters) {
          results.push(
            await runScanAdapter({
              adapter,
              profile,
              session: ctx.session,
              timeoutSeconds,
            }),
          );
        }

        const summaryArtifact = await writeWhiteboxArtifact({
          session: ctx.session,
          type: "static-scan",
          name: "scan-summary",
          content: JSON.stringify(results, null, 2),
          description: "Normalized whitebox scan summary",
          extension: ".json",
        });

        const totalFindings = results.reduce(
          (sum, result) => sum + result.findings.length,
          0,
        );

        return {
          success: true,
          summary: `Ran ${results.length} scanner(s), found ${totalFindings} summarized result(s).`,
          data: { results },
          artifactPaths: [
            summaryArtifact.path,
            ...results.map((result) => result.artifact.path),
          ],
          nextActions: [
            "Triage scanner output against reachability and attack path.",
            "Create whitebox candidates for plausible issues.",
            "Verify candidates dynamically or with reproducers before documenting findings.",
          ],
          truncated: false,
        };
      } catch (error) {
        return {
          success: false,
          summary: `Whitebox scan failed: ${error instanceof Error ? error.message : String(error)}`,
          artifactPaths: [],
          nextActions: [
            "Profile the codebase and retry with a narrower scanner kind.",
          ],
          recovery:
            "Check scanner installation, repo path, and command permissions.",
        };
      }
    },
  });
}
