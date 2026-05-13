import { tool } from "ai";
import { isAbsolute, resolve } from "path";
import { z } from "zod";
import {
  profileCodebase as buildRepoProfile,
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
whitebox catalog selection relevant to this repo. Use this early when source code is in scope.`,
    inputSchema: z.object({
      path: z
        .string()
        .optional()
        .describe(
          "Repository root to profile. Defaults to session.config.codebasePath or the agent working directory.",
        ),
      toolCallDescription: z
        .string()
        .describe("A concise description of the profiling task"),
    }),
    execute: async ({ path }) => {
      const rootPath = path
        ? isAbsolute(path)
          ? path
          : resolve(ctx.agentCwd, path)
        : (ctx.session.config?.codebasePath ?? ctx.agentCwd);

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
            profile,
            relevantCatalog: summarizeCatalogRecords(selection.records),
            recommendedPasses: summarizeCatalogRecords(
              selection.recommendedPasses,
            ),
          },
          artifactPaths: [artifact.path],
          nextActions: [
            "Use query_whitebox_catalog for focused sink or scanner guidance.",
            "Use run_code_query or spawn_coding_agent for targeted source-to-sink analysis.",
            "Use run_whitebox_scan for installed scanners that match this profile.",
          ],
          truncated: false,
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
