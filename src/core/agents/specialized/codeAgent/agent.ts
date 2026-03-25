import { stepCountIs } from "ai";
import type { z } from "zod";
import { OffensiveSecurityAgent } from "../../offSecAgent/offensiveSecurityAgent";
import type { SpecializedAgentInput } from "../../offSecAgent/types";
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
      callbacks,
      stopWhen,
      responseSchema,
      system,
      attackSurfaceRegistry,
    } = opts;

    const activeTools: string[] = [
      "read_file",
      "list_files",
      "grep",
      "execute_command",
      "document_asset",
      // Web search tools — research vulnerable library versions, look up API docs
      "web_search",
      "get_page",
    ];

    if (responseSchema) {
      activeTools.push("response");
    }

    super({
      system: system ?? CODE_AGENT_SYSTEM_PROMPT,
      prompt: buildPrompt(codebasePath, objective),
      model,
      session,
      authConfig,
      onStepFinish,
      onCacheMetrics,
      abortSignal,
      attackSurfaceRegistry,
      callbacks,
      subagentCallbacks: callbacks?.subagentCallbacks,
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
