import { tool } from "ai";
import { z } from "zod";
import { AgentEventBus } from "../../../eventBus";
import { newSessionId } from "../../../id/id";
import { runWithBoundedConcurrency } from "../../../utils/concurrency";
import {
  resolvePathWithinCodebaseRoot,
  resolveWhiteboxCodebaseRoot,
} from "../../../whitebox";
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
    execute: async ({ tasks }) => {
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

      // Shared primitive so each sub-agent inherits the OTel context. Errors
      // are caught per task and returned inline, so results never contain null.
      const settled = await runWithBoundedConcurrency(
        validatedTasks,
        DEFAULT_CONCURRENCY,
        async (item, i) => {
          try {
            const output = await runSingleCodingAgent(
              ctx,
              item.codebasePath,
              item.objective,
              i + 1,
              item.name,
            );
            return {
              codebasePath: item.codebasePath,
              objective: item.objective,
              output,
            };
          } catch (err) {
            return {
              codebasePath: item.codebasePath,
              objective: item.objective,
              output: "",
              error: err instanceof Error ? err.message : String(err),
            };
          }
        },
      );

      const results = settled.filter(
        (
          r,
        ): r is {
          codebasePath: string;
          objective: string;
          output: string;
          error?: string;
        } => r !== null,
      );

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
// Internal: run a single CodeAgent
// ---------------------------------------------------------------------------

async function runSingleCodingAgent(
  ctx: ToolContext,
  codebasePath: string,
  objective: string,
  agentIndex: number,
  name: string,
): Promise<string> {
  // Dynamic import to break circular dependency:
  // codeAgent → offensiveSecurityAgent → tools/index → spawnCodingAgent → codeAgent
  const { CodeAgent } = await import("../../specialized/codeAgent/agent");

  // The subagent IS a session; its id doubles as the bus identity (mirrors spawnPentestAgent).
  const childSessionId = newSessionId();
  const subagentId = childSessionId as string;

  ctx.eventBus?.emit("subagent-spawn", {
    subagentId,
    sessionId: childSessionId,
    name,
    input: { codebasePath, objective },
    parentSubagentId: ctx.subagentId,
    parentSessionId: ctx.subagentId ?? ctx.session.id,
  });

  const localBus = new AgentEventBus();
  let textOutput = "";
  AgentEventBus.attachChild(localBus, ctx.eventBus, subagentId);
  localBus.on("text-delta", (d) => {
    textOutput += d.text;
  });

  const agent = new CodeAgent({
    codebasePath,
    objective,
    model: ctx.model!,
    session: ctx.session,
    authConfig: ctx.authConfig,
    abortSignal: ctx.abortSignal,
    eventBus: localBus,
    subagentId,
    subagentName: name,
    enableThinking: ctx.enableThinking,
    thinkingEffort: ctx.thinkingEffort,
    openAIReasoningEffort: ctx.openAIReasoningEffort,
  });

  try {
    await agent.consume();

    ctx.eventBus?.emit("subagent-complete", {
      subagentId,
      sessionId: childSessionId,
      status: "completed",
      parentSubagentId: ctx.subagentId,
      parentSessionId: ctx.subagentId ?? ctx.session.id,
    });

    return textOutput;
  } catch (error) {
    ctx.eventBus?.emit("subagent-complete", {
      subagentId,
      sessionId: childSessionId,
      status: "failed",
      parentSubagentId: ctx.subagentId,
      parentSessionId: ctx.subagentId ?? ctx.session.id,
    });
    throw error;
  }
}
