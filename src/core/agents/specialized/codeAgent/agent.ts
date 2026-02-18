import { stepCountIs } from "ai";
import { OffensiveSecurityAgent } from "../../offSecAgent/offensiveSecurityAgent";
import type { SpecializedAgentInput } from "../../offSecAgent/types";
import { CODE_AGENT_SYSTEM_PROMPT } from "./prompts";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface CodeAgentInput extends SpecializedAgentInput {
  /** Root path of the codebase to work in (absolute path) */
  codebasePath: string;

  /** The specific objective for this agent to accomplish */
  objective: string;
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
export class CodeAgent extends OffensiveSecurityAgent<void> {
  constructor(opts: CodeAgentInput) {
    const {
      model,
      codebasePath,
      objective,
      session,
      authConfig,
      onStepFinish,
      abortSignal,
      callbacks,
      stopWhen,
    } = opts;

    super({
      system: CODE_AGENT_SYSTEM_PROMPT,
      prompt: buildPrompt(codebasePath, objective),
      model,
      session,
      authConfig,
      onStepFinish,
      abortSignal,
      callbacks,
      subagentCallbacks: callbacks?.subagentCallbacks,
      stopWhen: stopWhen ?? stepCountIs(10000),
      activeTools: [
        "read_file",
        "list_files",
        "grep",
        "execute_command",
        "document_asset",
      ],
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
