import type { StreamTextOnStepFinishCallback, ToolSet } from "ai";
import type { AIModel } from "../../../ai";
import type { AIAuthConfig } from "../../../ai/utils";
import { OffensiveSecurityAgent } from "../../offSecAgent/offensiveSecurityAgent";
import type { SessionInfo } from "../../../session";
import type { ConsumeCallbacks } from "../../offSecAgent/types";
import { CODE_AGENT_SYSTEM_PROMPT } from "./prompts";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface CodeAgentInput {
  /** Root path of the codebase to work in (absolute path) */
  codebasePath: string;

  /** The specific objective for this agent to accomplish */
  objective: string;

  /** AI model to drive the agent */
  model: AIModel;

  /** Session that provides paths for logs, scratchpad, etc. */
  session: SessionInfo;

  /** Optional per-provider API key overrides */
  authConfig?: AIAuthConfig;

  /** Optional callback after each agent step */
  onStepFinish?: StreamTextOnStepFinishCallback<ToolSet>;

  /** AbortSignal to cancel mid-run */
  abortSignal?: AbortSignal;

  /** Callbacks for stream events and subagent forwarding */
  callbacks?: ConsumeCallbacks;
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

      activeTools: ["read_file", "list_files", "grep", "execute_command"],
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
