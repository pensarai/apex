import { tool } from "ai";
import { z } from "zod";
import { jsonSchemaToZod } from "../../../../util/jsonSchemaToZod";
import { AgentEventBus } from "../../../eventBus";
import type { ToolContext } from "./types";

const DEFAULT_CONCURRENCY = 5;

interface SpawnCodingAgentTask {
  name: string;
  codebasePath: string;
  objective: string;
  responseSchema?: Record<string, unknown>;
}

interface SpawnCodingAgentResult {
  codebasePath: string;
  objective: string;
  output?: string;
  response?: unknown;
  error?: string;
}

export function spawnCodingAgent(ctx: ToolContext) {
  return tool({
    description: `Spawn one or more coding sub-agents to perform tasks on the codebase in parallel.

Each task gets its own autonomous agent with filesystem access (read_file, list_files, grep, execute_command). The agents work independently and return their text output when done.

Use this to fan out analysis work — e.g. analyze multiple apps, modules, or concerns in parallel for higher fidelity.

Each task needs:
- name: short human-readable label for the agent (shown in the UI)
- codebasePath: root directory for the agent to work in
- objective: a detailed description of what the agent should accomplish

Optionally, supply \`responseSchema\` (a JSON Schema object) to force the sub-agent to call a \`response\` tool with a validated JSON object instead of returning free-form text. When supplied, the result includes a typed \`response\` field instead of \`output\`. Use this when you need to consume the sub-agent's output programmatically — repo profiles, source-traces, normalized finding lists, etc.

Returns an array of results: one per task, each with either \`output\` (free-form) or \`response\` (validated structured object).`,
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
            responseSchema: z
              .record(z.string(), z.unknown())
              .optional()
              .describe(
                "Optional JSON Schema the sub-agent's final response must match. When provided, the sub-agent calls a `response` tool with a validated object; the result includes `response` instead of `output`. Use for profiles, traces, normalized findings, or any structured output you need to consume programmatically.",
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
      const results: SpawnCodingAgentResult[] = [];

      // Pre-convert responseSchema to zod once; invalid schemas fail-fast
      // without spinning up a sub-agent.
      type PreparedTask = SpawnCodingAgentTask & {
        index: number;
        zodSchema?: z.ZodTypeAny;
        schemaError?: string;
      };
      const queue: PreparedTask[] = tasks.map((t, i) => {
        const item: PreparedTask = { ...t, index: i };
        if (t.responseSchema !== undefined) {
          if (
            t.responseSchema === null ||
            typeof t.responseSchema !== "object"
          ) {
            item.schemaError =
              "Invalid responseSchema: must be a JSON Schema object";
          } else {
            try {
              item.zodSchema = jsonSchemaToZod(t.responseSchema);
            } catch (e) {
              item.schemaError = `Invalid responseSchema: ${e instanceof Error ? e.message : String(e)}`;
            }
          }
        }
        return item;
      });

      let active = 0;
      let idx = 0;

      await new Promise<void>((resolve) => {
        function next() {
          if (results.length === total) {
            resolve();
            return;
          }

          while (active < concurrency && idx < queue.length) {
            const item = queue[idx++];
            active++;

            if (item.schemaError) {
              results.push({
                codebasePath: item.codebasePath,
                objective: item.objective,
                error: item.schemaError,
              });
              active--;
              next();
              continue;
            }

            runSingleCodingAgent(
              ctx,
              item.codebasePath,
              item.objective,
              item.index + 1,
              item.name,
              item.zodSchema,
            )
              .then((res) => {
                results.push({
                  codebasePath: item.codebasePath,
                  objective: item.objective,
                  ...res,
                });
              })
              .catch((err) => {
                results.push({
                  codebasePath: item.codebasePath,
                  objective: item.objective,
                  error: err instanceof Error ? err.message : String(err),
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
        results,
        message: `Coding agents complete. ${total - failedTasks.length}/${total} succeeded.${
          failedTasks.length > 0 ? ` ${failedTasks.length} failed.` : ""
        }`,
      };
    },
  });
}

async function runSingleCodingAgent(
  ctx: ToolContext,
  codebasePath: string,
  objective: string,
  agentIndex: number,
  name: string,
  responseSchema?: z.ZodTypeAny,
): Promise<{ output?: string; response?: unknown; error?: string }> {
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

  const agent = new CodeAgent<unknown>({
    codebasePath,
    objective,
    model: ctx.model!,
    session: ctx.session,
    authConfig: ctx.authConfig,
    abortSignal: ctx.abortSignal,
    eventBus: localBus,
    subagentId,
    enableThinking: ctx.enableThinking,
    responseSchema,
  });

  try {
    const captured = await agent.consume();

    ctx.eventBus?.emit("subagent-complete", {
      subagentId,
      status: "completed",
      parentSubagentId: ctx.subagentId,
    });

    if (responseSchema) {
      if (captured === undefined) {
        return {
          error:
            "schema_validation_failed: sub-agent did not submit a structured response",
        };
      }
      return { response: captured };
    }

    return { output: textOutput };
  } catch (error) {
    ctx.eventBus?.emit("subagent-complete", {
      subagentId,
      status: "failed",
      parentSubagentId: ctx.subagentId,
    });
    throw error;
  }
}
