import { hasToolCall, stepCountIs } from "ai";
import { OffensiveSecurityAgent } from "../offSecAgent/offensiveSecurityAgent";
import { buildExplorationSystemPrompt } from "./prompts";
import type { ExplorationAgentInput } from "./types";

/**
 * Guided-onboarding exploration agent.
 *
 * A light, single-turn specialization of {@link OffensiveSecurityAgent}
 * that browses a cloned source repository with a small read-only toolset
 * and issues ONE batched `ask_user_questions` tool call before stopping.
 * Consumers collect the answers and feed them into downstream workflows
 * (e.g. whitebox recon) as user-provided context.
 *
 * Stop conditions:
 *   - `hasToolCall('ask_user_questions')` — the primary handshake.
 *   - `stepCountIs(40)` — hard cap in case the model never asks.
 *
 * The `askUserQuestionsEnabled: true` flag is the gate that causes the
 * base harness's `createAllTools` to actually include the
 * `ask_user_questions` tool factory in this agent's toolset. Without
 * the flag, listing the tool in `activeTools` would be a no-op.
 *
 * @example
 * ```ts
 * const agent = new ExplorationAgent({
 *   prompt: "Explore the repo at /workspace/acme-app and ask operator for context.",
 *   model: "claude-opus-4-6",
 *   session,
 * });
 * await agent.consume();
 * ```
 */
export class ExplorationAgent extends OffensiveSecurityAgent<void> {
  constructor(opts: ExplorationAgentInput) {
    super({
      system: buildExplorationSystemPrompt(),
      prompt: opts.prompt,
      model: opts.model,
      session: opts.session,
      authConfig: opts.authConfig,
      abortSignal: opts.abortSignal,
      onStepFinish: opts.onStepFinish,
      messages: opts.priorMessages,

      // Gate that causes createAllTools to include ask_user_questions for
      // this agent. Without this, the tool is not in the toolset even if
      // it is listed in activeTools.
      askUserQuestionsEnabled: true,

      activeTools: ["read_file", "list_files", "grep", "ask_user_questions"],

      stopWhen: [hasToolCall("ask_user_questions"), stepCountIs(40)],
    });
  }
}
