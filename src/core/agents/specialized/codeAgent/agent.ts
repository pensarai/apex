import { stepCountIs } from "ai";
import type { z } from "zod";
import {
  OffensiveSecurityAgent,
  type SpecializedAgentInput,
} from "../../offSecAgent";
import { CODE_AGENT_SYSTEM_PROMPT } from "./prompts";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface CodeAgentInput<TResult = void> extends SpecializedAgentInput {
  /** Root path of the codebase to work in (absolute path) */
  codebasePath: string;

  /** The specific objective for this agent to accomplish */
  objective: string;

  /**
   * Zod schema for structured output via the `response` tool.
   *
   * When provided, the agent gets a `response` tool that captures
   * validated structured data. `consume()` then returns `TResult`.
   */
  responseSchema?: z.ZodSchema;

  system?: string;

  /**
   * Tool names to exclude from the default CodeAgent toolset.
   * Useful for scoping agents to only the tools they need (e.g.
   * excluding `document_app` from endpoint-discovery agents).
   */
  excludeTools?: string[];
}

// ---------------------------------------------------------------------------
// CodeAgent
// ---------------------------------------------------------------------------

/**
 * A general-purpose coding subagent built on {@link OffensiveSecurityAgent}.
 *
 * Uses filesystem tools (`read_file`, `list_files`, `grep`) and
 * `execute_command` to navigate and analyze a codebase. Designed to be
 * spawned by a parent agent for a specific, well-defined task.
 *
 * @example
 * ```ts
 * const agent = new CodeAgent({
 *   codebasePath: "/app/target-project",
 *   objective: "Find all API endpoints that lack authentication middleware",
 *   model: "claude-sonnet-4-20250514",
 *   session,
 * });
 *
 * await agent.consume({
 *   onTextDelta: (d) => process.stdout.write(d.text),
 *   onToolCall:  (d) => console.log(`→ ${d.toolName}`),
 * });
 * ```
 */
/** The full default CodeAgent toolset, before any exclusions. */
export const CODE_AGENT_DEFAULT_TOOLS: readonly string[] = [
  "read_file",
  "list_files",
  "grep",
  "execute_command",
  "profile_codebase",
  "query_whitebox_catalog",
  "run_code_query",
  "run_whitebox_scan",
  "create_whitebox_candidate",
  "update_whitebox_candidate",
  "list_whitebox_candidates",
  "start_whitebox_job",
  "poll_whitebox_job",
  "stop_whitebox_job",
  "read_whitebox_artifact",
  "http_request",
  "document_app",
  "document_endpoint",
  // Web search tools — research vulnerable library versions, look up API docs
  "web_search",
  "get_page",
];

/**
 * Resolve the active tool list for a CodeAgent: the default toolset minus any
 * excluded tools, plus `response` when a structured-output schema is supplied.
 * Pure so callers (and tests) can see exactly which tools an agent will get —
 * e.g. that a blackbox threat-model agent ends up with no source-reading tools.
 */
export function resolveCodeAgentTools(
  excludeTools?: string[],
  hasResponseSchema = false,
): string[] {
  const excluded = new Set(excludeTools ?? []);
  const tools = CODE_AGENT_DEFAULT_TOOLS.filter((t) => !excluded.has(t));
  if (hasResponseSchema) tools.push("response");
  return tools;
}

export class CodeAgent<TResult = void> extends OffensiveSecurityAgent<TResult> {
  constructor(opts: CodeAgentInput<TResult>) {
    const {
      model,
      codebasePath,
      objective,
      session,
      authConfig,
      onStepFinish,
      onCacheMetrics,
      abortSignal,
      eventBus,
      subagentId,
      stopWhen,
      responseSchema,
      system,
      attackSurfaceRegistry,
      excludeTools,
      enableThinking,
      openAIReasoningEffort,
      projectThreatModel,
    } = opts;

    const activeTools = resolveCodeAgentTools(excludeTools, !!responseSchema);

    super({
      system: system ?? CODE_AGENT_SYSTEM_PROMPT,
      prompt: buildPrompt(codebasePath, objective),
      model,
      session,
      authConfig,
      onStepFinish,
      onCacheMetrics,
      abortSignal,
      eventBus,
      subagentId,
      attackSurfaceRegistry,
      enableThinking,
      openAIReasoningEffort,
      projectThreatModel,
      stopWhen: stopWhen ?? stepCountIs(10000),
      activeTools,
      responseSchema,
    });
  }
}

// ---------------------------------------------------------------------------
// Prompt builder
// ---------------------------------------------------------------------------

function buildPrompt(codebasePath: string, objective: string): string {
  return `# Objective

${objective}

## Codebase
- **Path:** ${codebasePath}

Begin now. Orient yourself in the codebase, then accomplish the objective.`;
}
