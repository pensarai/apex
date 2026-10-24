import { tool } from "ai";
import { z } from "zod";
import { getModelSettings } from "../../../ai";
import { type SpawnOptions, spawnBatch } from "../subagentSpawner";
import type { ToolContext } from "./types";

/** Default max concurrent recon workers. */
const DEFAULT_CONCURRENCY = 4;

/**
 * Factory for the `spawn_recon_agent` tool.
 *
 * Fans out one or more {@link ReconWorkerAgent} sub-agents, each pursuing a
 * single scoped goal with the same primitive toolset as the orchestrator
 * (browser, shell, HTTP, code tools, web search, clone_repository,
 * document_app). Workers cannot recursively spawn, which bounds the fan-out to
 * one level — the same pattern as `spawn_pentest_agent`.
 */
export function spawnReconAgent(ctx: ToolContext) {
  return tool({
    description: `Spawn one or more reconnaissance sub-agents to pursue scoped goals in parallel.

Each worker gets the same tools you have — browser automation, execute_command, http_request, the code tools, web_search/get_page, clone_repository (connected repos only), and document_app — but cannot spawn further workers or finalize the run.

Use this to fan out attack-surface mapping — e.g. "enumerate and threat-model the admin service", "map the api.example.com service to its repository and analyze it", "investigate the storage buckets referenced in the JS bundle".

Each task needs:
- name: short human-readable label shown in the UI
- goal: a detailed description of what this worker should accomplish
- target (optional): the origin/host the goal concerns
- codebasePath (optional): a cloned-repo path the goal concerns

Returns an array of results with each worker's text output.`,
    inputSchema: z.object({
      tasks: z
        .array(
          z.object({
            name: z
              .string()
              .describe(
                "Short human-readable label shown in the UI (e.g. 'admin service', 'api.example.com')",
              ),
            goal: z
              .string()
              .describe(
                "Detailed description of what this worker should accomplish",
              ),
            target: z
              .string()
              .optional()
              .describe("Origin/host the goal concerns, when applicable"),
            codebasePath: z
              .string()
              .optional()
              .describe("Cloned-repo path the goal concerns, when applicable"),
          }),
        )
        .describe("Array of goals to fan out to recon sub-agents"),
      toolCallDescription: z
        .string()
        .describe(
          "A concise, human-readable description of what this tool call is doing",
        ),
    }),
    execute: async ({ tasks }, { toolCallId }) => {
      if (!ctx.model) {
        return {
          success: false,
          message: "spawn_recon_agent requires a model in the tool context.",
          results: [],
        };
      }

      const total = tasks.length;
      const textOutputs = tasks.map(() => "");
      const settled = await spawnBatch(
        ctx.subagentSpawner,
        tasks.map((item, index) =>
          reconSpawnOptions(ctx, item, toolCallId, (text) => {
            textOutputs[index] += text;
          }),
        ),
        { concurrency: DEFAULT_CONCURRENCY },
      );

      const results = tasks.map((item, index) => {
        const result = settled[index]!;
        if (result.status === "rejected") {
          return {
            name: item.name,
            goal: item.goal,
            output: "",
            error:
              result.reason instanceof Error
                ? result.reason.message
                : String(result.reason),
          };
        }
        return {
          name: item.name,
          goal: item.goal,
          output: textOutputs[index]!,
          error: undefined,
        };
      });

      const failed = results.filter((r) => r.error);
      return {
        success: failed.length === 0,
        totalTasks: total,
        failedTasks: failed.length,
        results,
        message: `Recon workers complete. ${total - failed.length}/${total} succeeded.${
          failed.length > 0 ? ` ${failed.length} failed.` : ""
        }`,
      };
    },
  });
}

function reconSpawnOptions(
  ctx: ToolContext,
  item: { name: string; goal: string; target?: string; codebasePath?: string },
  parentToolCallId: string,
  onText: (text: string) => void,
): SpawnOptions<void> {
  return {
    spec: {
      type: "recon-worker",
      goal: item.goal,
      target: item.target,
      codebasePath: item.codebasePath,
      attackSurfaceRegistry: ctx.attackSurfaceRegistry,
    },
    runtime: {
      session: ctx.session,
      ...getModelSettings(ctx),
      abortSignal: ctx.abortSignal,
      sandbox: ctx.sandbox,
      backends: ctx.backends,
      credentialManager: ctx.credentialManager,
      environmentVariables: ctx.environmentVariables,
      secretValues: ctx.secretValues,
      languageModelMiddleware: ctx.languageModelMiddleware,
      usageRecorder: ctx.usageRecorder,
      toolExecutionContext: ctx.toolExecutionContext,
      streamIdFactory: ctx.streamIdFactory,
    },
    parentBus: ctx.eventBus,
    subagentName: item.name,
    lifecycleInput: { goal: item.goal, target: item.target },
    parentSubagentId: ctx.subagentId,
    parentSessionId: ctx.subagentId ?? ctx.session.id,
    parentToolCallId,
    stampChildSessionId: true,
    beforeConsume: (childBus) => {
      childBus.on("text-delta", (d) => {
        onText(d.text);
      });
    },
  };
}
