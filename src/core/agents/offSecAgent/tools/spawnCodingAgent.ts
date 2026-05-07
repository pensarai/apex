import { tool } from "ai";
import { z } from "zod";
import type { ToolContext } from "./types";
import { AgentEventBus } from "../../../eventBus";

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

Each task gets its own autonomous agent with filesystem access (read_file, list_files, grep, execute_command). The agents work independently and return their text output when done.

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

      const concurrency = DEFAULT_CONCURRENCY;
      const total = tasks.length;

      // Results accumulator
      const results: Array<{
        codebasePath: string;
        objective: string;
        output: string;
        error?: string;
      }> = [];

      // Bounded-concurrency executor
      let active = 0;
      let idx = 0;
      const queue = tasks.map((t, i) => ({ ...t, index: i }));

      await new Promise<void>((resolve) => {
        function next() {
          if (results.length === total) {
            resolve();
            return;
          }

          while (active < concurrency && idx < queue.length) {
            const item = queue[idx++];
            active++;

            runSingleCodingAgent(
              ctx,
              item.codebasePath,
              item.objective,
              item.index + 1,
              item.name,
            )
              .then((output) => {
                results.push({
                  codebasePath: item.codebasePath,
                  objective: item.objective,
                  output,
                });
              })
              .catch((err) => {
                results.push({
                  codebasePath: item.codebasePath,
                  objective: item.objective,
                  output: "",
                  error: err.message,
                });
              })
              .finally(() => {
                active--;
                next();
              });
          }
        }

        next();
      });

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

  const subagentId = `coding-agent-${agentIndex}`;

  ctx.eventBus?.emit("subagent-spawn", {
    subagentId,
    name,
    input: { codebasePath, objective },
    parentSubagentId: ctx.subagentId,
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
    enableThinking: ctx.enableThinking,
  });

  try {
    await agent.consume();

    ctx.eventBus?.emit("subagent-complete", {
      subagentId,
      status: "completed",
      parentSubagentId: ctx.subagentId,
    });

    return textOutput;
  } catch (error) {
    ctx.eventBus?.emit("subagent-complete", {
      subagentId,
      status: "failed",
      parentSubagentId: ctx.subagentId,
    });
    throw error;
  }
}
