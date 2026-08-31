import { tool } from "ai";
import { z } from "zod";
import type { ScanKind } from "../../../whitebox";
import {
  profileCodebase,
  resolvePathWithinCodebaseRoot,
  resolveWhiteboxCodebaseRoot,
  runScanAdapter,
  selectScanAdaptersWithMeta,
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
          "Repository root to scan; must stay under the configured codebase root.",
        ),
      kind: ScanKindSchema.optional().describe("Restrict scan family"),
      scannerIds: z
        .array(z.string())
        .max(20)
        .optional()
        .describe("Specific adapter IDs to run, e.g. semgrep, gitleaks"),
      timeoutSeconds: z
        .number()
        .int()
        .positive()
        .max(3600)
        .optional()
        .describe("Per-scanner timeout in seconds. Defaults to 120, max 3600."),
      toolCallDescription: z
        .string()
        .optional()
        .describe("A concise description of the scan"),
    }),
    execute: async ({ path, kind, scannerIds, timeoutSeconds = 120 }) => {
      const codebaseRoot = resolveWhiteboxCodebaseRoot({
        agentCwd: ctx.agentCwd,
        codebasePath: ctx.session.config?.codebasePath,
      });
      let rootPath: string;
      try {
        rootPath = path
          ? resolvePathWithinCodebaseRoot(codebaseRoot, path)
          : codebaseRoot;
      } catch (error) {
        return {
          success: false,
          summary: error instanceof Error ? error.message : String(error),
          artifactPaths: [],
          nextActions: ["Use a scan path inside the configured codebase root."],
          recovery:
            "Paths are constrained to session.config.codebasePath (or agent cwd).",
        };
      }

      try {
        const profile = await profileCodebase(rootPath);
        const { adapters, unknownScannerIds } = selectScanAdaptersWithMeta({
          profile,
          kind: kind as ScanKind | undefined,
          scannerIds,
        });

        if (adapters.length === 0) {
          return {
            success: false,
            summary: unknownScannerIds.length
              ? `No scanners to run (unknown ids: ${unknownScannerIds.join(", ")}).`
              : "No applicable installed whitebox scanners found.",
            data: {
              requested: { kind, scannerIds },
              unknownScannerIds,
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
              unknownScannerIds.length > 0
                ? "Remove unknown scanner ids or install matching tools."
                : "Install one of the relevant scanners or run a code-query pass instead.",
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

        const scannerSummaries = results.map((result) => ({
          scanner: result.scanner,
          exitCode: result.exitCode,
          findingCount: result.findings.length,
          outputTruncated: result.outputTruncated ?? false,
          timedOut: result.timedOut ?? false,
          artifactPath: result.artifact.path,
        }));

        const anyFailed = results.some(
          (r) =>
            r.timedOut ||
            r.exitCode === null ||
            (r.exitCode !== 0 && r.exitCode !== 1),
        );

        return {
          success: !anyFailed,
          summary: anyFailed
            ? `Ran ${results.length} scanner(s) (some failed/timed out), found ${totalFindings} summarized result(s).`
            : `Ran ${results.length} scanner(s), found ${totalFindings} summarized result(s).`,
          data: {
            scanners: scannerSummaries,
            unknownScannerIds,
          },
          artifactPaths: [
            summaryArtifact.path,
            ...results.map((result) => result.artifact.path),
          ],
          nextActions: [
            "Use read_whitebox_artifact for raw scanner logs and full summaries on disk.",
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
