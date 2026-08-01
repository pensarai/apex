import { resolve } from "node:path";
import { tool } from "ai";
import { z } from "zod";
import type { ToolContext } from "./types";

export function runWhiteboxRecon(ctx: ToolContext) {
  return tool({
    description: `Profile a local source repository's externally relevant attack surface.

This read-only workflow performs a complete file census, organizes deployable
applications, executes deterministic selectors over every eligible file,
analyzes only finite evidence bundles, reconciles canonical application buckets,
and verifies every file and candidate disposition.
It inventories HTTP, GraphQL, gRPC, network interfaces, infrastructure identity,
and application resources. It does not perform penetration testing.`,
    inputSchema: z.object({
      cwd: z
        .string()
        .optional()
        .describe(
          "Repository path. Defaults to the operator working directory.",
        ),
      maxConcurrentWorkers: z
        .number()
        .int()
        .min(1)
        .max(4)
        .optional()
        .describe("Maximum concurrent map workers. Defaults to 4."),
      toolCallDescription: z
        .string()
        .describe(
          "A concise description such as 'Profiling repository attack surface'",
        ),
    }),
    execute: async ({ cwd, maxConcurrentWorkers }) => {
      if (!ctx.model) {
        return {
          success: false,
          message: "run_whitebox_recon requires a model in the tool context.",
        };
      }

      try {
        const { runWhiteboxRecon: run } = await import(
          "../../../whiteboxRecon"
        );
        const output = await run({
          codebasePath: cwd ? resolve(ctx.agentCwd, cwd) : ctx.agentCwd,
          model: ctx.model,
          session: ctx.session,
          authConfig: ctx.authConfig,
          abortSignal: ctx.abortSignal,
          eventBus: ctx.eventBus,
          openAIReasoningEffort: ctx.openAIReasoningEffort,
          maxConcurrentWorkers,
        });
        const { result, artifacts } = output;
        return {
          success: true,
          status: result.status,
          applications: result.applications.length,
          surfaces: result.surfaces.length,
          resources: result.resources.length,
          unresolved: result.unresolved.length,
          filesScanned: result.metrics.files_reviewed,
          filesRelevant: result.metrics.files_relevant,
          candidates: result.metrics.candidates_total,
          bundles: result.metrics.shards_total,
          bundleCacheHits: result.metrics.bundle_cache_hits,
          modelCalls: result.metrics.agent_calls,
          tokensIn: result.metrics.tokens_in,
          tokensOut: result.metrics.tokens_out,
          resultPath: artifacts.result,
          inventoryPath: artifacts.inventory,
          observationsPath: artifacts.observations,
          metricsPath: artifacts.metrics,
          message:
            result.status === "complete"
              ? `Whitebox recon complete: ${result.surfaces.length} interfaces across ${result.applications.length} applications. Result: ${artifacts.result}`
              : `Whitebox recon incomplete: ${result.unresolved.length} items require investigation. Partial result: ${artifacts.result}`,
        };
      } catch (error) {
        if (error instanceof Error && error.name === "AbortError") {
          return {
            success: false,
            message: "Whitebox recon was aborted by the user.",
          };
        }
        const message = error instanceof Error ? error.message : String(error);
        return {
          success: false,
          message: `Whitebox recon failed: ${message}`,
        };
      }
    },
  });
}
