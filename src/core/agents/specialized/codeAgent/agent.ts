import { stepCountIs } from "ai";
import type { z } from "zod";
import {
  type AgentDefinition,
  AgentRuntime,
  type SpecializedAgentInput,
} from "../../offSecAgent";
import { CODE_AGENT_SYSTEM_PROMPT } from "./prompts";

const CODE_AGENT_TOOLS: string[] = [
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

const CODE_AGENT_DEFINITION = {
  type: "code",
  systemPrompt: CODE_AGENT_SYSTEM_PROMPT,
  activeTools: CODE_AGENT_TOOLS,
  stopWhen: stepCountIs(10000),
} satisfies AgentDefinition;

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
export class CodeAgent<TResult = void> extends AgentRuntime<TResult> {
  constructor(opts: CodeAgentInput<TResult>) {
    const { codebasePath, objective, system, responseSchema, excludeTools, ...base } =
      opts;

    let activeTools = [...CODE_AGENT_TOOLS];
    if (excludeTools?.length) {
      const excluded = new Set(excludeTools);
      activeTools = activeTools.filter((t) => !excluded.has(t));
    }
    if (responseSchema) {
      activeTools.push("response");
    }

    super({
      ...base,
      definition: CODE_AGENT_DEFINITION,
      prompt: buildPrompt(codebasePath, objective),
      system: system ?? CODE_AGENT_SYSTEM_PROMPT,
      activeTools,
      responseSchema,
      stopWhen: base.stopWhen ?? stepCountIs(10000),
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
