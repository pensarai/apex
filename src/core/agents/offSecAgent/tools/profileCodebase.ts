import { tool } from "ai";
import { z } from "zod";
import {
  profileCodebase as buildRepoProfile,
  resolvePathWithinCodebaseRoot,
  resolveWhiteboxCodebaseRoot,
  selectCatalogForProfile,
  summarizeCatalogRecords,
  writeWhiteboxArtifact,
} from "../../../whitebox";
import type { ToolContext } from "./types";

export function profileCodebase(ctx: ToolContext) {
  return tool({
    description: `Profile a local source-code repository for whitebox security assessment.

Returns languages, package managers, manifests, build/test/run hints, entry-point hints,
IaC/CI files, native-code indicators, installed scanner availability, and a narrow
whitebox catalog selection relevant to this repo. Use this early when source code is in scope.
Full structured output is written to the session artifact; inline data is a compact summary.`,
    inputSchema: z.object({
      path: z
        .string()
        .optional()
        .describe(
          "Repository root to profile, relative to the configured codebase root or absolute if still under that root.",
        ),
      toolCallDescription: z
        .string()
        .describe("A concise description of the profiling task"),
    }),
    execute: async ({ path }) => {
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
          nextActions: ["Use a path inside the configured codebase root."],
          recovery:
            "Paths are constrained to session.config.codebasePath (or agent cwd) to avoid accidental out-of-scope reads.",
        };
      }

      try {
        const profile = await buildRepoProfile(rootPath);
        const selection = selectCatalogForProfile(profile);
        const artifact = await writeWhiteboxArtifact({
          session: ctx.session,
          type: "repo-profile",
          name: "repo-profile",
          content: JSON.stringify({ profile, catalog: selection }, null, 2),
          description:
            "Whitebox repository profile and relevant catalog records",
          extension: ".json",
        });

        return {
          success: true,
          summary: `Profiled ${rootPath}: languages=${profile.languages.join(", ")}, packageManagers=${profile.packageManagers.join(", ") || "none"}, entryHints=${profile.entryPointHints.length}, iac=${profile.iacFiles.length}, ci=${profile.ciFiles.length}.`,
          data: {
            rootPath: profile.rootPath,
            languages: profile.languages,
            packageManagers: profile.packageManagers,
            manifestFilesCount: profile.manifestFiles.length,
            lockfilesCount: profile.lockfiles.length,
            entryPointHintsSample: profile.entryPointHints.slice(0, 15),
            iacFilesCount: profile.iacFiles.length,
            ciFilesCount: profile.ciFiles.length,
            nativeCode: profile.nativeCode,
            relevantCatalog: summarizeCatalogRecords(selection.records),
            recommendedPasses: summarizeCatalogRecords(
              selection.recommendedPasses,
            ),
          },
          artifactPaths: [artifact.path],
          nextActions: [
            "Use read_whitebox_artifact with the artifact path for the full JSON profile.",
            "Use query_whitebox_catalog for focused sink or scanner guidance.",
            "Use run_code_query or spawn_coding_agent for targeted source-to-sink analysis.",
            "Use run_whitebox_scan for installed scanners that match this profile.",
          ],
          truncated: profile.entryPointHints.length > 15,
        };
      } catch (error) {
        return {
          success: false,
          summary: `Failed to profile codebase: ${error instanceof Error ? error.message : String(error)}`,
          artifactPaths: [],
          nextActions: [
            "Check that the path exists and is a readable directory.",
          ],
          recovery: "Use list_files on the intended codebase root, then retry.",
        };
      }
    },
  });
}
