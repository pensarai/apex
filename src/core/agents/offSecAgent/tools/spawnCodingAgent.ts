import { tool } from "ai";
import { z } from "zod";
import { getModelSettings } from "../../../ai";
import type { AssetRecord } from "../../../findings/attackSurfaceRegistry";
import {
  resolvePathWithinCodebaseRoot,
  resolveWhiteboxCodebaseRoot,
} from "../../../whitebox";
import { type SpawnOptions, spawnBatch } from "../subagentSpawner";
import type { ToolContext } from "./types";

/** Default max concurrent coding agents */
const DEFAULT_CONCURRENCY = 5;

/**
 * Factory for the `spawn_coding_agent` tool.
 *
 * Launches one or more {@link CodeAgent} instances in parallel, each
 * with its own objective. The parent agent can fan out work — e.g.
 * "analyze app A" and "analyze app B" simultaneously — then collect
 * the text output from each.
 */
export function spawnCodingAgent(ctx: ToolContext) {
  return tool({
    description: `Spawn one or more coding sub-agents to perform tasks on the codebase in parallel.

Each task gets its own autonomous CodeAgent with filesystem tools plus whitebox helpers
(profile_codebase, query_whitebox_catalog, run_code_query, run_whitebox_scan, candidates, bounded jobs,
read_whitebox_artifact), plus execute_command, http_request, web_search, and document_app/document_endpoint.
The agents work independently and return their text output when done.

Use this to fan out analysis work — e.g. analyze multiple apps, modules, or concerns in parallel for higher fidelity.

Each task needs:
- codebasePath: root directory for the agent to work in
- objective: a detailed description of what the agent should accomplish

Returns an array of results with the text output from each agent.`,
    inputSchema: z.object({
      tasks: z
        .array(
          z.object({
            name: z
              .string()
              .describe(
                "Short human-readable label for this agent shown in the UI (e.g. 'parseurl module', 'auth middleware')",
              ),
            codebasePath: z
              .string()
              .describe("Root directory for this agent to work in"),
            objective: z
              .string()
              .describe(
                "Detailed description of what this agent should accomplish",
              ),
          }),
        )
        .describe("Array of tasks to fan out to coding sub-agents"),
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
          message: "spawn_coding_agent requires a model in the tool context.",
          results: [],
        };
      }

      const codebaseRoot = resolveWhiteboxCodebaseRoot({
        agentCwd: ctx.agentCwd,
        codebasePath: ctx.session.config?.codebasePath,
      });

      const validatedTasks: typeof tasks = [];
      for (const t of tasks) {
        try {
          validatedTasks.push({
            ...t,
            codebasePath: resolvePathWithinCodebaseRoot(
              codebaseRoot,
              t.codebasePath,
            ),
          });
        } catch {
          return {
            success: false,
            message: `Coding agent codebasePath "${t.codebasePath}" escapes the configured codebase root.`,
            results: [],
            recovery:
              "Use paths inside the configured codebase root (session.config.codebasePath or agent cwd).",
          };
        }
      }

      const total = validatedTasks.length;

      const spawner = ctx.subagentSpawner;

      const textOutputs = validatedTasks.map(() => "");
      const settled = await spawnBatch(
        spawner,
        validatedTasks.map((item, index) =>
          codingSpawnOptions(
            ctx,
            item.codebasePath,
            item.objective,
            item.name,
            toolCallId,
            (text) => {
              textOutputs[index] += text;
            },
          ),
        ),
        { concurrency: DEFAULT_CONCURRENCY },
      );
      const results = [];
      for (const [index, item] of validatedTasks.entries()) {
        const result = settled[index]!;
        try {
          if (result.status === "rejected") throw result.reason;
          if (result.value?.surface?.length && ctx.attackSurfaceRegistry) {
            for (const asset of result.value.surface) {
              await ctx.attackSurfaceRegistry.register(asset);
            }
          }
          results.push({
            ...item,
            output: result.value?.text ?? textOutputs[index]!,
            error: undefined,
          });
        } catch (error) {
          results.push({
            ...item,
            output: "",
            error: error instanceof Error ? error.message : String(error),
          });
        }
      }

      const failedTasks = results.filter((r) => r.error);

      return {
        success: failedTasks.length === 0,
        totalTasks: total,
        failedTasks: failedTasks.length,
        results: results.map((r) => ({
          codebasePath: r.codebasePath,
          objective: r.objective,
          output: r.output,
          error: r.error,
        })),
        message: `Coding agents complete. ${total - failedTasks.length}/${total} succeeded.${
          failedTasks.length > 0 ? ` ${failedTasks.length} failed.` : ""
        }`,
      };
    },
  });
}

// ---------------------------------------------------------------------------
// Child request
// ---------------------------------------------------------------------------

/** The slice of a durable CodeAgent child's returned value the parent folds. */
interface CodingChildResult {
  surface?: AssetRecord[];
  text?: string;
}

function codingSpawnOptions(
  ctx: ToolContext,
  codebasePath: string,
  objective: string,
  name: string,
  parentToolCallId: string,
  onText: (text: string) => void,
): SpawnOptions<CodingChildResult | undefined> {
  return {
    spec: { type: "code", codebasePath, objective },
    runtime: {
      findingPolicy: ctx.findingPolicy,
      session: ctx.session,
      ...getModelSettings(ctx),
      abortSignal: ctx.abortSignal,
      sandbox: ctx.sandbox,
      backends: ctx.backends,
      environmentVariables: ctx.environmentVariables,
      secretValues: ctx.secretValues,
      languageModelMiddleware: ctx.languageModelMiddleware,
      toolProtocol: ctx.toolProtocol,
      usageRecorder: ctx.usageRecorder,
      toolExecutionContext: ctx.toolExecutionContext,
      streamIdFactory: ctx.streamIdFactory,
    },
    parentBus: ctx.eventBus,
    subagentName: name,
    lifecycleInput: { codebasePath, objective },
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
