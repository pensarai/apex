import { tool } from "ai";
import { z } from "zod";
import { jsonSchemaToZod } from "../../../../util/jsonSchemaToZod";
import { AgentEventBus } from "../../../eventBus";
import type { ToolContext } from "./types";

/** Default max concurrent coding agents */
const DEFAULT_CONCURRENCY = 5;

/**
 * Per-task input shape (single-source-of-truth for both the public input
 * schema and the internal queue item).
 */
interface SpawnCodingAgentTask {
  name: string;
  codebasePath: string;
  objective: string;
  responseSchema?: Record<string, unknown>;
}

/**
 * Per-task result shape returned from {@link spawnCodingAgent}.
 *
 * When the task supplied a `responseSchema`, the validated `response`
 * object is included and `output` is omitted. When no schema is supplied
 * (backward-compatible path), the agent's free-form text `output` is
 * returned and `response` is omitted.
 *
 * When schema validation fails after the run, both fields may be omitted
 * and `error` carries the validation issues.
 */
interface SpawnCodingAgentResult {
  codebasePath: string;
  objective: string;
  output?: string;
  response?: unknown;
  error?: string;
}

/**
 * Factory for the `spawn_coding_agent` tool.
 *
 * Launches one or more {@link CodeAgent} instances in parallel, each
 * with its own objective. The parent agent can fan out work — e.g.
 * "analyze app A" and "analyze app B" simultaneously — then collect
 * the text output or typed structured response from each.
 *
 * Pass a JSON-Schema-shaped `responseSchema` on a task to constrain the
 * sub-agent's final output. The schema is converted to zod internally,
 * routed through {@link CodeAgent}'s existing `responseSchema` slot, and
 * the validated object is returned as `response`. Validation failures
 * are surfaced per-task as `error: "schema_validation_failed"` so the
 * parent can decide whether to retry or fall back.
 */
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
                "Optional JSON Schema (Draft-7 subset) the sub-agent's final response must match. When provided, the sub-agent calls a `response` tool with a validated object; the result includes `response` instead of `output`. Use for profiles, traces, normalized findings, or any structured output you need to consume programmatically.",
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

      // Pre-convert each task's responseSchema to zod once. Failure here
      // means the parent agent supplied an invalid schema — fail this
      // task immediately rather than spinning up a sub-agent that can't
      // capture a valid response.
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

            // Short-circuit invalid schema: no sub-agent runs.
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

// ---------------------------------------------------------------------------
// Internal: run a single CodeAgent
// ---------------------------------------------------------------------------

/**
 * Run one sub-agent and return either its free-form text output (when
 * `responseSchema` is omitted) or its validated structured response.
 *
 * When a schema is supplied and the sub-agent never calls the response
 * tool (or calls it with an invalid payload), the returned object
 * carries `error: "schema_validation_failed"` instead of throwing — the
 * parent agent decides how to react.
 */
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
      // CodeAgent's default resolveResult returns `undefined` when the
      // sub-agent never called the response tool. Treat that as a
      // validation failure so the parent can react.
      if (captured === undefined) {
        return {
          error:
            "schema_validation_failed: sub-agent did not submit a structured response",
        };
      }
      // The response tool already validated the payload against the
      // zod schema at tool-call time — we trust `captured` here.
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
